package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/go-chi/chi/v5"
)

type dashboardData struct {
	Containers   interface{} `json:"containers"`
	DecisionCount int        `json:"decision_count"`
	BouncerCount  int        `json:"bouncer_count"`
	ProxyType     string     `json:"proxy_type"`
	Features      interface{} `json:"features"`
}

// RegisterDashboardRoutes mounts the dashboard endpoints.
func RegisterDashboardRoutes(r chi.Router, deps *api.Dependencies) {
	r.Get("/api/dashboard", handleGetDashboard(deps))
}

func handleGetDashboard(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		containers, err := deps.Docker.ListContainers(ctx)
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		decisionCount := 0
		output, err := deps.Docker.ExecInContainer(ctx, deps.Config.CrowdSecContainer, []string{
			"cscli", "decisions", "list", "-o", "json",
		})
		if err == nil && output != "" {
			var decisions []interface{}
			if json.Unmarshal([]byte(output), &decisions) == nil {
				decisionCount = len(decisions)
			}
		}

		bouncerCount := 0
		adapter := deps.ProxyManager.Adapter()
		if adapter != nil {
			bm := adapter.BouncerManager()
			if status, err := bm.Status(ctx); err == nil {
				bouncerCount = status.Count
			}
		}

		data := dashboardData{
			Containers:    containers,
			DecisionCount: decisionCount,
			BouncerCount:  bouncerCount,
			ProxyType:     string(deps.ProxyManager.ProxyType()),
			Features:      deps.ProxyManager.SupportedFeatures(),
		}

		api.JSON(w, http.StatusOK, api.Success(data))
	}
}
