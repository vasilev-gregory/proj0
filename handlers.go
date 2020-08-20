package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi"
	"golang.org/x/crypto/bcrypt"
)

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
	db.Find(&users)
	reqID, _ := strconv.Atoi(id)
	if len(users) < reqID {
		response(w, http.StatusNotFound, "try lower ID")
		return false
	}
	return true
}

func GetAll(w http.ResponseWriter, r *http.Request) {
	db.Find(&users)
	jsn, _ := json.Marshal(users)
	w.Write(jsn)
	response(w, http.StatusOK, "all users")
}

func Create(w http.ResponseWriter, r *http.Request) {
	var userIn UserIn
	var tmp []User

	err := json.NewDecoder(r.Body).Decode(&userIn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// fmt.Fprintf(w, "password: %+v \n", userIn.Password)
	userIn.Password, _ = HashPassword(userIn.Password)
	// fmt.Fprintf(w, "hash: %+v", userIn.Password)

	u := User(userIn)
	db.Where("name = ?", userIn.Name).Find(&tmp)
	var message string
	if len(tmp) == 0 {
		db.Create(&u)

		ujson, _ := json.Marshal(u)
		w.Write(ujson)
		message = "new user at the bottom"
	} else {
		message = "choose another name"
	}

	response(w, http.StatusOK, message)
}

func Update(w http.ResponseWriter, r *http.Request) {
	requestedID := chi.URLParam(r, "ID")

	if !isValidID(w, requestedID) {
		return
	}
	// проверка на то, чтобы ID был меньше, чем строчек в таблице

	var userIn UserIn

	err := json.NewDecoder(r.Body).Decode(&userIn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db.Where("name = ?", userIn.Name).Find(&users)
	if len(users) > 0 {
		response(w, http.StatusOK, "choose another name")
		return
	}
	// проверка на уникальности имени

	// fmt.Fprintf(w, "password: %+v \n", userIn.Password)
	userIn.Password, _ = HashPassword(userIn.Password)
	// fmt.Fprintf(w, "hash: %+v", userIn.Password)

	db.Model(&users).Where("ID = ?", requestedID).Update(userIn)
	db.Find(&users)
	ujson, _ := json.Marshal(users[reqID-1])
	w.Write(ujson)

	response(w, http.StatusOK, fmt.Sprintf("new user at ID = %v", requestedID))
}

func Auth(w http.ResponseWriter, r *http.Request) {
	var (
		loginPassword UserIn
		user          User
	)

	err := json.NewDecoder(r.Body).Decode(&loginPassword)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// fmt.Fprintf(w, "login: %+v \n password: %+v \n", loginPassword.Name, loginPassword.Password)

	db.Raw("SELECT name, password FROM users WHERE name = ?", loginPassword.Name).Scan(&user)

	// fmt.Fprintf(w, "login: %+v \n hash: %+v \n", user.Name, user.Password)

	var message string
	if CheckPasswordHash(loginPassword.Password, user.Password) {
		message = fmt.Sprintf("%+v logged in", user.Name)
	} else {
		message = fmt.Sprintf("wrong login or password")
	}

	response(w, http.StatusOK, message)
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
	requestedID := chi.URLParam(r, "ID")
	db.Where("ID = ?", requestedID).Delete(&users)
	response(w, http.StatusOK, fmt.Sprintf("user at ID = %v was deleted", requestedID))
}
