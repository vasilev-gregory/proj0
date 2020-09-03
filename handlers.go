package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/imdario/mergo"

	"github.com/go-chi/chi"
)

func GetAll(w http.ResponseWriter, r *http.Request) {
	db.Find(&users)
	resp(w, http.StatusOK, "all users", users)
}

func Create(w http.ResponseWriter, r *http.Request) {
	var userIn UserIn

	err := json.NewDecoder(r.Body).Decode(&userIn)
	if err != nil {
		resp(w, http.StatusBadRequest, err.Error())
		return
	}
	// читаем в UserIn

	userIn.Password, _ = HashPassword(userIn.Password)
	// хэшим пароль

	if !isValidName(w, userIn.Name) || !isValidAge(w, userIn.Age) || !isValidRole(w, &userIn.Role) {
		return
	}
	// проверяем уникальность имени и валидность возраста

	u := User(userIn)
	dbAdmin.Create(&u)
	// добавляем новую строку в дб

	var us User
	dbAdmin.Where("name = ?", u.Name).Find(&us)

	resp(w, http.StatusOK, "new user waiting for admin approval", []User{us})
	// выводим статус выполнения задачи
}

func Update(w http.ResponseWriter, r *http.Request) {
	requestedID := chi.URLParam(r, "ID")

	var userIn UserIn
	err := json.NewDecoder(r.Body).Decode(&userIn)
	if err != nil {
		resp(w, http.StatusBadRequest, err.Error())
		return
	}
	// считываем введенную строку в userIn

	if len(userIn.Password) > 0 {
		userIn.Password, _ = HashPassword(userIn.Password)
		// хэшим пароль
	}

	var user User
	db.Where("ID = ?", requestedID).Find(&user)
	// запись, в которую надо внести изменения
	nu := User(userIn)
	// изменения
	mergo.Merge(&nu, user)
	// изменения внесены, новая записть в nu
	if !isValidName(w, nu.Name, requestedID) || !isValidAge(w, nu.Age) || !isValidRole(w, &nu.Role) {
		return
	}
	// уникальность имени
	// валидность возраста
	// проверить валидность роли в получившейся записи

	db.Model(&users).Where("ID = ?", requestedID).Update(&nu)
	// добавляем готовую и проверенную строку в дб

	var u User
	db.Where("name = ?", nu.Name).Find(&u)

	resp(w, http.StatusOK, fmt.Sprintf("user updated"), []User{u})
	// выводим статус выполнения задачи
}

func Login(w http.ResponseWriter, r *http.Request) {
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
		resp(w, http.StatusUnauthorized, "wrong login or password")
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
		resp(w, http.StatusInternalServerError, "error in creating the JWT")
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
	resp(w, http.StatusOK, fmt.Sprintf("user at ID = %v", requestedID), []User{userID})
}

func Del(w http.ResponseWriter, r *http.Request) {
	requestedID := chi.URLParam(r, "ID")
	db.Where("ID = ?", requestedID).Delete(&users)
	resp(w, http.StatusOK, fmt.Sprintf("user at ID = %v was deleted", requestedID))
}

func GetNew(w http.ResponseWriter, r *http.Request) {
	var user User
	dbAdmin.Last(&user)
	resp(w, http.StatusOK, "APPROVE or DELETE", []User{user})
}

func GetAllNew(w http.ResponseWriter, r *http.Request) {
	dbAdmin.Find(&users)
	resp(w, http.StatusOK, "all users", users)
}

func ApproveNew(w http.ResponseWriter, r *http.Request) {
	var appUser ApproveUser
	var user User

	err := json.NewDecoder(r.Body).Decode(&appUser)
	if err != nil {
		resp(w, http.StatusBadRequest, "decoding went wrong")
		return
	}
	// достали ответ админа, что делать с юзером
	// и если есть - изменения

	dbAdmin.Last(&user)
	// достали последнюю запись

	nu := User(appUser.NewUser)
	//впринципе можно перекинуть в кейс апрув
	if appUser.Approval == "APPROVE" {
		mergo.Merge(&nu, user)
		// если были внесены изменения, их внесли
		// новый пользовательс админскими изменениями
		// в nu

		if !isValidRole(w, &nu.Role) || !isValidName(w, nu.Name) || !isValidAge(w, nu.Age) {
			return
		}
		// проверка валидности роли готовой строки, раньше ее не сделать

		nu.ID = 0 // не знаю почему, но без этого выдает ошибку на след строке
		//вообще непонятно откуда он берет значение для айди

		db.Create(&nu)
		// закинули в основную базу

		var u User
		db.Where("name = ?", user.Name).Find(&u)
		resp(w, http.StatusOK, "new user approved", []User{u})
		// выводим статус выполнения задачи

		dbAdmin.Where("id = ?", user.ID).Delete(&users)
		// то, что обработали, удалили
	} else if appUser.Approval == "DELETE" {
		dbAdmin.Where("id = ?", user.ID).Delete(&users)
		resp(w, http.StatusOK, "application deleted")
	} else {
		resp(w, http.StatusBadRequest, "cant understand what shoild i do :(")
	}

}
