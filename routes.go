package main

import (
	"net/http"

	"github.com/go-chi/chi"
)

func Routes() {
	r := chi.NewRouter()

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("root"))
	})

	r.Route("/", func(r chi.Router) {
		r.Get("/users", GetAll)
		r.Post("/users", Create)
		r.Post("/users/auth", Auth)
		r.Get("/users/{ID:[0-9]+}", GetOne)
		r.Post("/users/{ID:[0-9]+}", Update)
		r.Delete("/users/{ID:[0-9]+}", Del)
	})
	http.ListenAndServe(":3337", r)
}
