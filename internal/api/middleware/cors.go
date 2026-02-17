package middleware

import (
	"net/http"

	"github.com/rs/cors"
)

// CORS returns a CORS middleware handler. In dev mode it allows localhost:5173
// for the Vite dev server. In production it allows same-origin only.
func CORS(devMode bool) func(http.Handler) http.Handler {
	var origins []string
	if devMode {
		origins = []string{
			"http://localhost:5173",
			"http://127.0.0.1:5173",
			"http://localhost:8080",
		}
	}

	c := cors.New(cors.Options{
		AllowedOrigins:   origins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           300,
	})

	return c.Handler
}
