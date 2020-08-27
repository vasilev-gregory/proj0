package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/go-chi/chi"
)

func GetAll(w http.ResponseWriter, r *http.Request) {
	db.Find(&users)
	jsn, _ := json.Marshal(users)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsn)
	// все юзеры наружу
	response(w, http.StatusOK, "all users")
}

func Create(w http.ResponseWriter, r *http.Request) {
	var userIn UserIn

	err := json.NewDecoder(r.Body).Decode(&userIn)
	if err != nil {
		response(w, http.StatusBadRequest, err.Error())
		return
	}
	// читаем в UserIn

	userIn.Password, _ = HashPassword(userIn.Password)
	// хэшим пароль

	if !isValidName(w, userIn.Name) || !isValidAge(w, userIn.Age) {
		return
	}
	// проверяем уникальность имени и валидность возраста

	u := User(userIn)
	db.Create(&u)
	// добавляем новую строку в дб

	ujson, _ := json.Marshal(u)
	w.Header().Set("Content-Type", "application/json")
	w.Write(ujson)
	// выводим новую строку

	response(w, http.StatusOK, "new user at the bottom")
	// выводим статус выполнения задачи
}

func Update(w http.ResponseWriter, r *http.Request) {
	requestedID := chi.URLParam(r, "ID")

	if !isValidToken(w, r, requestedID) {
		return
	}

	var userIn UserIn
	err := json.NewDecoder(r.Body).Decode(&userIn)
	if err != nil {
		response(w, http.StatusBadRequest, err.Error())
		return
	}
	// считываем введенную строку в UserIn

	if !isValidID(w, requestedID) || !isValidName(w, userIn.Name, requestedID) || !isValidAge(w, userIn.Age) {
		return
	}
	// проверка валидности айди
	// уникальность имени
	// валидность возраста

	userIn.Password, _ = HashPassword(userIn.Password)
	// хэшим пароль

	db.Model(&users).Where("ID = ?", requestedID).Update(&userIn)
	// добавляем готовую и проверенную строку в дб

	var u User
	db.Where("name = ?", userIn.Name).Find(&u)
	ujson, _ := json.Marshal(u)
	w.Header().Set("Content-Type", "application/json")
	w.Write(ujson)
	// выводим в тело добавленную строку

	response(w, http.StatusOK, fmt.Sprintf("user updated"))
	// выводим статус выполнения задачи
}

func Auth(w http.ResponseWriter, r *http.Request) {
	var (
		loginPassword UserIn // это читаем
		user          User   // с этим сравниваем
	)

	err := json.NewDecoder(r.Body).Decode(&loginPassword)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// считали от клиента логин-пароль

	db.Raw("SELECT ID, name, password FROM users WHERE name = ?", loginPassword.Name).Scan(&user)
	// нашли в бд строку с считанным именем

	if !CheckPasswordHash(loginPassword.Password, user.Password) {
		response(w, http.StatusUnauthorized, "wrong login or password")
		return
	}
	// пара логин-пароль невалидна, выдаем статус и вылетаем

	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(5 * time.Minute)

	// Create the JWT claims, which includes the ID and expiry time
	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		Id:        fmt.Sprint(user.ID), // токен выдается по ID!!! Это значит, что если id сможет меняться, надо этот кусок изменить!
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		response(w, http.StatusInternalServerError, "error in creating the JWT")
		return
	}

	stText := []byte(http.StatusText(http.StatusOK))
	mapD := map[string]string{
		"message":         "valid login-password",
		"status_text":     string(stText),
		"access_token":    tokenString,
		"expiration_time": expirationTime.Format("2006-01-02T15:04:05.999999-07:00"),
		"id":              fmt.Sprint(user.ID),
	}
	mapB, _ := json.Marshal(mapD)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(mapB)
}

func GetOne(w http.ResponseWriter, r *http.Request) {
	requestedID := chi.URLParam(r, "ID")
	var userID User
	db.First(&userID, requestedID)
	jsnID, _ := json.Marshal(userID)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsnID)
	response(w, http.StatusOK, fmt.Sprintf("user at ID = %v", requestedID))
}

func Del(w http.ResponseWriter, r *http.Request) {
	requestedID := chi.URLParam(r, "ID")
	if !isValidToken(w, r, requestedID) {
		return
	}
	db.Where("ID = ?", requestedID).Delete(&users)
	response(w, http.StatusOK, fmt.Sprintf("user at ID = %v was deleted", requestedID))
}

// func OnlyAdmin(h http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		if r.Method == "OPTIONS" {
// 			h.ServeHTTP(w, r)
// 		} else {
// 			tokenString, _ := jwtmiddleware.FromAuthHeader(r)
// 			if !matchRole(tokenString, "admin") {
// 				customRoleError(w, "Отказано в доступе", 403)
// 				return
// 			}

// 			h.ServeHTTP(w, r)
// 		}
// 	})
// }
