package handlers

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

func resolveCrowdsecLogService(service string, cfg *config.Config) (string, bool) {
	if service == "crowdsec" || service == cfg.CrowdsecContainerName {
		return cfg.CrowdsecContainerName, true
	}
	return "", false
}

// GetCrowdSecLogs retrieves CrowdSec logs
func GetCrowdSecLogs(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		tail := c.DefaultQuery("tail", "100")
		logger.Info("Getting CrowdSec logs", "tail", tail)

		logs, err := dockerClient.GetContainerLogs(cfg.CrowdsecContainerName, tail)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("Failed to get logs: %v", err)})
			return
		}

		c.JSON(http.StatusOK, models.Response{Success: true, Data: gin.H{"logs": logs}})
	}
}

// GetServiceLogs gets logs for crowdsec service only
func GetServiceLogs(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		serviceParam := c.Param("service")
		service, ok := resolveCrowdsecLogService(serviceParam, cfg)
		if !ok {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Only crowdsec logs are supported"})
			return
		}

		tail := c.DefaultQuery("tail", "100")
		logger.Info("Getting service logs", "service", service, "tail", tail)

		logs, err := dockerClient.GetContainerLogs(service, tail)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("Failed to get logs: %v", err)})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"logs": logs, "service": service},
		})
	}
}

// StreamLogs streams logs via WebSocket using Docker's native Follow mode
func StreamLogs(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	var upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		serviceParam := c.Param("service")
		service, ok := resolveCrowdsecLogService(serviceParam, cfg)
		if !ok {
			upgradeHeader := c.GetHeader("Upgrade")
			if strings.EqualFold(upgradeHeader, "websocket") || strings.EqualFold(c.Request.Header.Get("Upgrade"), "websocket") {
				c.Header("Connection", "close")
				c.String(http.StatusBadRequest, "Only crowdsec logs are supported")
				return
			}
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Only crowdsec logs are supported"})
			return
		}

		logger.Info("Streaming logs", "service", service)

		ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			logger.Error("Failed to upgrade to websocket", "error", err)
			return
		}
		defer ws.Close()

		ws.SetReadDeadline(time.Now().Add(60 * time.Second))
		ws.SetPongHandler(func(string) error {
			ws.SetReadDeadline(time.Now().Add(60 * time.Second))
			return nil
		})

		pingTicker := time.NewTicker(30 * time.Second)
		defer pingTicker.Stop()

		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				_, _, err := ws.ReadMessage()
				if err != nil {
					logger.Debug("WebSocket read error", "error", err)
					return
				}
			}
		}()

		since := time.Now().Add(-5 * time.Minute).Format(time.RFC3339)
		logStream, err := dockerClient.FollowContainerLogs(service, since)
		if err != nil {
			ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error starting log stream: %v", err)))
			return
		}
		defer logStream.Close()

		logLines := make(chan string, 64)
		logErr := make(chan error, 1)

		go func() {
			defer close(logLines)
			header := make([]byte, 8)
			for {
				if _, err := io.ReadFull(logStream, header); err != nil {
					logErr <- err
					return
				}
				size := int(header[4])<<24 | int(header[5])<<16 | int(header[6])<<8 | int(header[7])
				if size <= 0 {
					continue
				}
				payload := make([]byte, size)
				if _, err := io.ReadFull(logStream, payload); err != nil {
					logErr <- err
					return
				}
				line := strings.TrimRight(string(payload), "\r\n")
				if line != "" {
					logLines <- line
				}
			}
		}()

		for {
			select {
			case <-done:
				return
			case <-pingTicker.C:
				if err := ws.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
					logger.Debug("WebSocket ping error", "error", err)
					return
				}
			case line, ok := <-logLines:
				if !ok {
					select {
					case streamErr := <-logErr:
						if streamErr != nil && streamErr != io.EOF {
							ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Log stream ended: %v", streamErr)))
						}
					default:
					}
					return
				}
				if err := ws.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
					logger.Debug("WebSocket write error", "error", err)
					return
				}
			}
		}
	}
}

// GetStructuredLogs returns parsed, structured log entries for crowdsec container
func GetStructuredLogs(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		serviceParam := c.Param("service")
		service, ok := resolveCrowdsecLogService(serviceParam, cfg)
		if !ok {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Only crowdsec logs are supported"})
			return
		}

		tail := c.DefaultQuery("tail", "200")
		level := c.DefaultQuery("level", "")

		logger.Info("Getting structured logs", "service", service, "tail", tail)

		entries, err := dockerClient.GetStructuredLogs(service, tail, service)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("Failed to get structured logs: %v", err)})
			return
		}

		if level != "" {
			filtered := make([]docker.StructuredLogEntry, 0)
			for _, e := range entries {
				if e.Level == level {
					filtered = append(filtered, e)
				}
			}
			entries = filtered
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: gin.H{
				"entries": entries,
				"count":   len(entries),
				"service": service,
			},
		})
	}
}
