package handlers

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/go-chi/chi/v5"
)

type allowlistRequest struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

// RegisterAllowlistRoutes mounts CrowdSec allowlist endpoints.
func RegisterAllowlistRoutes(r chi.Router, deps *api.Dependencies) {
	r.Route("/api/allowlist", func(r chi.Router) {
		r.Get("/", handleListAllowlist(deps))
		r.Post("/", handleAddAllowlist(deps))
		r.Delete("/{ip}", handleRemoveAllowlist(deps))
	})
}

func handleListAllowlist(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		output, err := deps.Docker.ExecInContainer(r.Context(), deps.Config.CrowdSecContainer, []string{
			"cscli", "allowlists", "list", "-o", "json",
		})
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		var data interface{}
		if json.Unmarshal([]byte(output), &data) != nil {
			data = output
		}
		api.JSON(w, http.StatusOK, api.Success(data))
	}
}

func handleAddAllowlist(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req allowlistRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("invalid request body"))
			return
		}

		if net.ParseIP(req.IP) == nil {
			if _, _, err := net.ParseCIDR(req.IP); err != nil {
				api.JSON(w, http.StatusBadRequest, api.ErrMsg("invalid IP address or CIDR"))
				return
			}
		}

		reason := req.Reason
		if reason == "" {
			reason = "added via manager"
		}

		_, err := deps.Docker.ExecInContainer(r.Context(), deps.Config.CrowdSecContainer, []string{
			"cscli", "allowlists", "add", req.IP, "--reason", reason,
		})
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("IP added to allowlist: "+req.IP))
	}
}

func handleRemoveAllowlist(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := chi.URLParam(r, "ip")
		if ip == "" {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("IP parameter required"))
			return
		}

		_, err := deps.Docker.ExecInContainer(r.Context(), deps.Config.CrowdSecContainer, []string{
			"cscli", "allowlists", "remove", ip,
		})
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("IP removed from allowlist: "+ip))
	}
}
