package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/go-chi/chi"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("secret")

type tokens struct {
	AccessToken    string `json:"access_token"`
	ExpirationTime string `json:"expiration_time`
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func response(w http.ResponseWriter, code int, message string) {
	stText := []byte(http.StatusText(code))
	mapD := map[string]string{"message": message, "status_text": string(stText)}
	mapB, _ := json.Marshal(mapD)
	w.WriteHeader(code)
	w.Write(mapB)
}

func isValidID(w http.ResponseWriter, id string) bool {
	reqID, _ := strconv.Atoi(id)
	db.Find(&users)
	if len(users) < reqID {
		response(w, http.StatusNotFound, "try lower ID")
		return false
	}
	return true
}

func isValidName(w http.ResponseWriter, name string) bool {
	var tmp []User
	db.Where("name = ?", name).Find(&tmp)
	if len(tmp) == 0 {
		return true
	}
	response(w, http.StatusOK, "choose another name")
	return false
}

func isValidAge(w http.ResponseWriter, age int) bool {
	if age > 0 && age < 130 {
		return true
	}
	response(w, http.StatusOK, "something wrong with age")
	return false
}

func isValidToken(w http.ResponseWriter, r *http.Request, onlyForAdmins bool) bool {
	tknStr := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	// Initialize a new instance of `Claims`
	claims := &jwt.StandardClaims{}

	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(tknStr[1], claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			response(w, http.StatusUnauthorized, "ErrSignatureInvalid")
			return false
		}
		response(w, http.StatusBadRequest, "something wrong")
		return false
	}
	if !tkn.Valid {
		response(w, http.StatusUnauthorized, "time is up")
		return false
	}
	var u User
	db.Where("id = ?", claims.Id).Find(&u)
	if onlyForAdmins == true && u.IsAdmin == false {
		response(w, http.StatusForbidden, "need to be admin")
		return false
	}

	return true
}

func GetAll(w http.ResponseWriter, r *http.Request) {
	db.Find(&users)
	jsn, _ := json.Marshal(users)
	w.Write(jsn)
	// все юзеры наружу
	response(w, http.StatusOK, "all users")
}

func Create(w http.ResponseWriter, r *http.Request) {
	if !isValidToken(w, r, true) {
		return
	}

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
	w.Write(ujson)
	// выводим новую строку

	response(w, http.StatusOK, "new user at the bottom")
	// выводим статус выполнения задачи
}

func Update(w http.ResponseWriter, r *http.Request) {
	if !isValidToken(w, r, true) {
		return
	}

	requestedID := chi.URLParam(r, "ID")

	var userIn UserIn
	err := json.NewDecoder(r.Body).Decode(&userIn)
	if err != nil {
		response(w, http.StatusBadRequest, err.Error())
		return
	}
	// считываем введенную строку в UserIn

	if !isValidID(w, requestedID) || !isValidName(w, userIn.Name) || !isValidAge(w, userIn.Age) {
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
	w.Write(ujson)
	// выводим в тело добавленную строку

	response(w, http.StatusOK, fmt.Sprintf("new user at ID = %v", requestedID))
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

	tkns := tokens{
		AccessToken:    tokenString,
		ExpirationTime: expirationTime.Format("2006-01-02T15:04:05.999999-07:00"),
	}

	response(w, http.StatusOK, "valid login-password, token is out without any problems, and you are:")
	jsn, _ := json.Marshal(user)
	w.Write(jsn)
	jsn1, _ := json.Marshal(tkns)
	w.Write(jsn1)
}

func GetOne(w http.ResponseWriter, r *http.Request) {
	requestedID := chi.URLParam(r, "ID")
	var userID User
	db.First(&userID, requestedID)
	jsnID, _ := json.Marshal(userID)
	w.Write(jsnID)
	response(w, http.StatusOK, fmt.Sprintf("user at ID = %v", requestedID))
}

func Del(w http.ResponseWriter, r *http.Request) {
	if !isValidToken(w, r, true) {
		return
	}
	requestedID := chi.URLParam(r, "ID")
	db.Where("ID = ?", requestedID).Delete(&users)
	response(w, http.StatusOK, fmt.Sprintf("user at ID = %v was deleted", requestedID))
}
