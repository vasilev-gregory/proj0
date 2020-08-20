package main

import (
	"encoding/json"
	"fmt"
	"net/http"

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

func response(w http.ResponseWriter, r *http.Request, code int, massage string) {
	stText := []byte(http.StatusText(code))
	mapD := map[string]string{"massage": massage, "status_text": string(stText)}
	mapB, _ := json.Marshal(mapD)
	w.WriteHeader(code)
	w.Write(mapB)
}

func GetAll(w http.ResponseWriter, r *http.Request) {
	db.Find(&users)
	jsn, _ := json.Marshal(users)
	w.Write(jsn)
	response(w, r, http.StatusOK, "all users")
}

func Post(w http.ResponseWriter, r *http.Request) {
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
	var massage string
	if len(tmp) == 0 {
		db.Create(&u)

		ujson, _ := json.Marshal(u)
		w.Write(ujson)
		massage = "new user at the bottom"
	} else {
		massage = "choose another name"
	}

	response(w, r, http.StatusOK, massage)
}

func PostOne(w http.ResponseWriter, r *http.Request) {
	requestedID := chi.URLParam(r, "ID")

	var userIn UserIn

	err := json.NewDecoder(r.Body).Decode(&userIn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// fmt.Fprintf(w, "password: %+v \n", userIn.Password)
	userIn.Password, _ = HashPassword(userIn.Password)
	// fmt.Fprintf(w, "hash: %+v", userIn.Password)

	db.Model(&users).Where("ID = ?", requestedID).Update(userIn)

	ujson, _ := json.Marshal(User(userIn))
	w.Write(ujson)

	response(w, r, http.StatusOK, fmt.Sprintf("new user at ID = %v", requestedID))
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

	var massage string
	if CheckPasswordHash(loginPassword.Password, user.Password) {
		massage = fmt.Sprintf("%+v logged in", user.Name)
	} else {
		massage = fmt.Sprintf("wrong login or password")
	}

	response(w, r, http.StatusOK, massage)
}

func GetOne(w http.ResponseWriter, r *http.Request) {
	requestedID := chi.URLParam(r, "ID")
	var userID User
	db.First(&userID, requestedID)
	jsnID, _ := json.Marshal(userID)
	w.Write(jsnID)
	response(w, r, http.StatusOK, fmt.Sprintf("user at ID = %v", requestedID))
}

func DelOne(w http.ResponseWriter, r *http.Request) {
	requestedID := chi.URLParam(r, "ID")
	db.Where("ID = ?", requestedID).Delete(&users)
	response(w, r, http.StatusOK, fmt.Sprintf("user at ID = %v was deleted", requestedID))
}
