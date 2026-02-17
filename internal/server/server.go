package server

import (
	"io/fs"
	"net/http"
	"os"
	"strings"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/crowdsecurity/crowdsec-manager/internal/api/middleware"
	"github.com/go-chi/chi/v5"
)

// New creates a fully configured Chi router with all middleware and routes.
func New(deps *api.Dependencies) http.Handler {
	r := chi.NewRouter()

	// Middleware stack.
	r.Use(middleware.Recovery)
	r.Use(middleware.Logging)
	r.Use(middleware.CORS(deps.Config.DevMode))

	// API routes.
	RegisterAll(r, deps)

	// Serve the SPA from ./ui/dist with fallback to index.html.
	serveSPA(r)

	return r
}

// serveSPA serves static files from the ui/dist directory. Unknown paths
// fall back to index.html so the SPA router can handle client-side routes.
func serveSPA(r chi.Router) {
	distDir := "./ui/dist"

	if _, err := os.Stat(distDir); os.IsNotExist(err) {
		// No UI build available; skip static file serving.
		return
	}

	fsys := os.DirFS(distDir)
	fileServer := http.FileServer(http.FS(fsys))

	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")

		// Try to serve the exact file first.
		if f, err := fs.Stat(fsys, path); err == nil && !f.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}

		// Fallback: serve index.html for SPA routing.
		indexBytes, err := fs.ReadFile(fsys, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexBytes)
	})
}
