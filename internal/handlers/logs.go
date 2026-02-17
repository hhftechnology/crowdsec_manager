package handlers

import (
	"bufio"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// RegisterLogsRoutes mounts log retrieval and WebSocket streaming endpoints.
func RegisterLogsRoutes(r chi.Router, deps *api.Dependencies) {
	r.Get("/api/logs", handleGetLogs(deps))
	r.Get("/api/ws/logs", handleStreamLogsWS(deps))
}

func handleGetLogs(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		service := r.URL.Query().Get("service")
		if service == "" {
			service = deps.Config.CrowdSecContainer
		}

		lines := 100
		if l := r.URL.Query().Get("lines"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
				lines = parsed
			}
		}

		// Try proxy log manager first.
		adapter := deps.ProxyManager.Adapter()
		if adapter != nil && service == deps.Config.ProxyContainer {
			opts := proxy.LogOptions{Service: service, Lines: lines}
			entries, err := adapter.LogManager().GetLogs(r.Context(), opts)
			if err == nil {
				api.JSON(w, http.StatusOK, api.Success(entries))
				return
			}
		}

		// Fallback to raw Docker logs.
		raw, err := deps.Docker.GetContainerLogs(r.Context(), service, lines)
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.Success(map[string]interface{}{
			"service": service,
			"lines":   raw,
		}))
	}
}

func handleStreamLogsWS(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			slog.Error("websocket upgrade failed", "error", err)
			return
		}
		defer conn.Close()

		service := r.URL.Query().Get("service")
		if service == "" {
			service = deps.Config.CrowdSecContainer
		}

		ctx := r.Context()
		reader, err := deps.Docker.StreamContainerLogs(ctx, service)
		if err != nil {
			conn.WriteJSON(map[string]string{"error": err.Error()})
			return
		}
		defer reader.Close()

		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
				line := scanner.Text()
				if err := conn.WriteJSON(map[string]string{"line": line, "service": service}); err != nil {
					return
				}
			}
		}
	}
}
