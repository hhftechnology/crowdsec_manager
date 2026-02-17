package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
	"github.com/go-chi/chi/v5"
)

// RegisterWhitelistRoutes mounts whitelist management endpoints.
func RegisterWhitelistRoutes(r chi.Router, deps *api.Dependencies) {
	r.Route("/api/whitelist", func(r chi.Router) {
		r.Get("/", handleListWhitelist(deps))
		r.Post("/", handleAddWhitelist(deps))
		r.Post("/current-ip", handleWhitelistCurrentIP(deps))
		r.Delete("/{ip}", handleRemoveWhitelist(deps))
	})
}

func handleListWhitelist(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adapter := deps.ProxyManager.Adapter()
		if adapter == nil {
			api.JSON(w, http.StatusOK, api.Success([]interface{}{}))
			return
		}

		entries, err := adapter.WhitelistManager().List(r.Context())
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}
		if entries == nil {
			entries = []proxy.WhitelistEntry{}
		}
		api.JSON(w, http.StatusOK, api.Success(entries))
	}
}

func handleAddWhitelist(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var entry proxy.WhitelistEntry
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("invalid request body"))
			return
		}

		if net.ParseIP(entry.IP) == nil {
			// Allow CIDR notation.
			if _, _, err := net.ParseCIDR(entry.IP); err != nil {
				api.JSON(w, http.StatusBadRequest, api.ErrMsg("invalid IP address or CIDR"))
				return
			}
		}

		adapter := deps.ProxyManager.Adapter()
		if adapter == nil {
			api.JSON(w, http.StatusServiceUnavailable, api.ErrMsg("no proxy adapter available"))
			return
		}

		if err := adapter.WhitelistManager().Add(r.Context(), entry); err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("IP whitelisted: "+entry.IP))
	}
}

func handleWhitelistCurrentIP(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := extractClientIP(r)
		if ip == "" {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("could not determine client IP"))
			return
		}

		adapter := deps.ProxyManager.Adapter()
		if adapter == nil {
			api.JSON(w, http.StatusServiceUnavailable, api.ErrMsg("no proxy adapter available"))
			return
		}

		entry := proxy.WhitelistEntry{
			IP:     ip,
			Source: "auto",
			Reason: "whitelisted via current-ip endpoint",
		}
		if err := adapter.WhitelistManager().Add(r.Context(), entry); err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("current IP whitelisted: "+ip))
	}
}

func handleRemoveWhitelist(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := chi.URLParam(r, "ip")
		if ip == "" {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("IP parameter required"))
			return
		}

		adapter := deps.ProxyManager.Adapter()
		if adapter == nil {
			api.JSON(w, http.StatusServiceUnavailable, api.ErrMsg("no proxy adapter available"))
			return
		}

		if err := adapter.WhitelistManager().Remove(r.Context(), ip); err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("IP removed from whitelist: "+ip))
	}
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}
