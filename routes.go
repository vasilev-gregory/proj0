package main

import (
	"net/http"

	"github.com/chi/middleware"
	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

func Routes() {
	r := chi.NewRouter()
	r.Use(
		render.SetContentType(render.ContentTypeJSON), // Set content-Type headers as application/json
		middleware.Logger,          // Log API request calls
		middleware.RedirectSlashes, // Redirect slashes to no slash URL versions
		middleware.Recoverer,       // Recover from panics without crashing server
	)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("root"))
	})

	r.Route("/users", func(r chi.Router) {
		//anon
		r.Get("/", GetAll)
		r.Post("/", Create)
		r.Post("/login", Login)
		//admin or user
		r.With(RequireAuthentication).Route("/{ID:[0-9]+}", func(r chi.Router) {
			r.Get("/", GetOne)
			r.Put("/", Update)
			r.Delete("/", Del)
		})

	})
	http.ListenAndServe(":3337", r)
}
