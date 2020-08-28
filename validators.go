package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("secret")

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func response(w http.ResponseWriter, code int, message string, users ...[]User) {
	type responseType struct {
		Users      []User `json:"users"`
		Message    string `json:"message"`
		StatusText string `json:"status_text"`
	}
	stText := http.StatusText(code)
	rspns := responseType{Message: message, StatusText: stText}
	if len(users) != 0 {
		rspns.Users = users[0]
	}
	mapB, _ := json.Marshal(rspns)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(mapB)
}

func isValidID(w http.ResponseWriter, id string) bool {
	reqID, _ := strconv.Atoi(id)
	db.Find(&users)
	if int(users[len(users)-1].ID) < reqID {
		response(w, http.StatusNotFound, "try lower ID")
		return false
	}
	return true
}

func isValidName(w http.ResponseWriter, name string, id ...string) bool {
	var tmp []User
	db.Where("name = ?", name).Find(&tmp)
	if len(tmp) == 0 || (len(id) != 0 && fmt.Sprint(tmp[0].ID) == id[0]) {
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

func RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			next.ServeHTTP(w, r)
			return
		}

		tknStr := jwtauth.TokenFromHeader(r)
		if len(tknStr) == 0 {
			response(w, http.StatusBadRequest, "need token")
			return
		}
		// Initialize a new instance of `Claims`
		claims := &jwt.StandardClaims{}
		// Parse the JWT string and store the result in `claims`.
		// Note that we are passing the key in this method as well. This method will return an error
		// if the token is invalid (if it has expired according to the expiry time we set on sign in),
		// or if the signature does not match
		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				response(w, http.StatusUnauthorized, "ErrSignatureInvalid")
				return
			}
			response(w, http.StatusBadRequest, "something wrong with token")
			return
		}
		if !tkn.Valid {
			response(w, http.StatusUnauthorized, "time is up")
			return
		}

		id := chi.URLParam(r, "ID")
		var u User
		db.Where("id = ?", claims.Id).Find(&u)
		if u.IsAdmin == false && id != claims.Id {
			response(w, http.StatusForbidden, "access denied")
			return
		}
		// Assuming that passed, we can execute the authenticated handler
		next.ServeHTTP(w, r)
	})
}
