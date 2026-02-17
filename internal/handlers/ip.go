package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/go-chi/chi/v5"
)

type ipRequest struct {
	IP string `json:"ip"`
}

type publicIPResult struct {
	IP string `json:"ip"`
}

// RegisterIPRoutes mounts IP management endpoints.
func RegisterIPRoutes(r chi.Router, deps *api.Dependencies) {
	r.Route("/api/ip", func(r chi.Router) {
		r.Get("/public", handleGetPublicIP(deps))
		r.Post("/check-blocked", handleCheckBlocked(deps))
		r.Post("/security-check", handleSecurityCheck(deps))
		r.Post("/unban", handleUnban(deps))
	})
}

func handleGetPublicIP(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Try to determine the public IP via CrowdSec container.
		output, err := deps.Docker.ExecInContainer(r.Context(), deps.Config.CrowdSecContainer, []string{
			"sh", "-c", "wget -qO- https://ifconfig.me 2>/dev/null || curl -s https://ifconfig.me 2>/dev/null || echo unknown",
		})
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}
		ip := strings.TrimSpace(output)
		api.JSON(w, http.StatusOK, api.Success(publicIPResult{IP: ip}))
	}
}

func handleCheckBlocked(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ipRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("invalid request body"))
			return
		}

		if net.ParseIP(req.IP) == nil {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("invalid IP address"))
			return
		}

		// SAFE: IP is validated above, passed as separate argument.
		output, err := deps.Docker.ExecInContainer(r.Context(), deps.Config.CrowdSecContainer, []string{
			"cscli", "decisions", "list", "--ip", req.IP, "-o", "json",
		})
		if err != nil {
			// Exit code 1 means no decisions found.
			api.JSON(w, http.StatusOK, api.Success(map[string]interface{}{
				"blocked":   false,
				"ip":        req.IP,
				"decisions": []interface{}{},
			}))
			return
		}

		var decisions []interface{}
		if json.Unmarshal([]byte(output), &decisions) != nil {
			decisions = []interface{}{}
		}

		api.JSON(w, http.StatusOK, api.Success(map[string]interface{}{
			"blocked":   len(decisions) > 0,
			"ip":        req.IP,
			"decisions": decisions,
		}))
	}
}

func handleSecurityCheck(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ipRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("invalid request body"))
			return
		}

		if net.ParseIP(req.IP) == nil {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("invalid IP address"))
			return
		}

		// Check decisions.
		decisionsOutput, _ := deps.Docker.ExecInContainer(r.Context(), deps.Config.CrowdSecContainer, []string{
			"cscli", "decisions", "list", "--ip", req.IP, "-o", "json",
		})
		var decisions []interface{}
		json.Unmarshal([]byte(decisionsOutput), &decisions)

		// Check alerts.
		alertsOutput, _ := deps.Docker.ExecInContainer(r.Context(), deps.Config.CrowdSecContainer, []string{
			"cscli", "alerts", "list", "--ip", req.IP, "-o", "json",
		})
		var alerts []interface{}
		json.Unmarshal([]byte(alertsOutput), &alerts)

		api.JSON(w, http.StatusOK, api.Success(map[string]interface{}{
			"ip":        req.IP,
			"blocked":   len(decisions) > 0,
			"decisions": decisions,
			"alerts":    alerts,
		}))
	}
}

func handleUnban(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ipRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("invalid request body"))
			return
		}

		if net.ParseIP(req.IP) == nil {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("invalid IP address"))
			return
		}

		_, err := deps.Docker.ExecInContainer(r.Context(), deps.Config.CrowdSecContainer, []string{
			"cscli", "decisions", "delete", "--ip", req.IP,
		})
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("IP unbanned: "+req.IP))
	}
}
