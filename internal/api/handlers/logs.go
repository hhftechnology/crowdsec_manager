package handlers

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// =============================================================================
// LOGS
// =============================================================================

// GetCrowdSecLogs retrieves CrowdSec logs
func GetCrowdSecLogs(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		tail := c.DefaultQuery("tail", "100")
		logger.Info("Getting CrowdSec logs", "tail", tail)

		logs, err := dockerClient.GetContainerLogs(cfg.CrowdsecContainerName, tail)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get logs: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"logs": logs},
		})
	}
}

// GetTraefikLogs retrieves Traefik logs from the access log file
func GetTraefikLogs(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		tail := c.DefaultQuery("tail", "100")
		logType := c.DefaultQuery("type", "access") // access or error
		logger.Info("Getting Traefik logs", "tail", tail, "type", logType)

		settings, _ := db.GetSettings()
		var logPath string
		if logType == "error" {
			logPath = settings.TraefikErrorLog
		} else {
			logPath = settings.TraefikAccessLog
		}

		// Read log file from traefik container
		logs, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{"tail", "-n", tail, logPath})
		if err != nil {
			// Fallback to container logs if file reading fails
			logger.Warn("Failed to read log file, falling back to container logs", "error", err)
			logs, err = dockerClient.GetContainerLogs(cfg.TraefikContainerName, tail)
			if err != nil {
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to get logs: %v", err),
				})
				return
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"logs": logs, "path": logPath},
		})
	}
}

// AnalyzeTraefikLogsAdvanced performs advanced analysis of Traefik logs
func AnalyzeTraefikLogsAdvanced(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		tail := c.DefaultQuery("tail", "1000")
		logger.Info("Analyzing Traefik logs", "tail", tail)

		logs, err := dockerClient.GetContainerLogs(cfg.TraefikContainerName, tail)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get logs: %v", err),
			})
			return
		}

		// Parse and analyze logs
		stats := analyzeLogs(logs)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    stats,
		})
	}
}

// GetServiceLogs gets logs for any service
func GetServiceLogs(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		service := c.Param("service")
		tail := c.DefaultQuery("tail", "100")
		logger.Info("Getting service logs", "service", service, "tail", tail)

		logs, err := dockerClient.GetContainerLogs(service, tail)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get logs: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"logs": logs, "service": service},
		})
	}
}

// StreamLogs streams logs via WebSocket using Docker's native Follow mode
func StreamLogs(dockerClient *docker.Client) gin.HandlerFunc {
	var upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		service := c.Param("service")
		logger.Info("Streaming logs", "service", service)

		ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			logger.Error("Failed to upgrade to websocket", "error", err)
			return
		}
		defer ws.Close()

		// Set up ping/pong handlers
		ws.SetReadDeadline(time.Now().Add(60 * time.Second))
		ws.SetPongHandler(func(string) error {
			ws.SetReadDeadline(time.Now().Add(60 * time.Second))
			return nil
		})

		pingTicker := time.NewTicker(30 * time.Second)
		defer pingTicker.Stop()

		done := make(chan struct{})

		// Read messages from client (to detect disconnection)
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

		// Start Docker follow stream
		since := time.Now().Add(-5 * time.Minute).Format(time.RFC3339)
		logStream, err := dockerClient.FollowContainerLogs(service, since)
		if err != nil {
			ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error starting log stream: %v", err)))
			return
		}
		defer logStream.Close()

		// Stream log lines from Docker to WebSocket in a goroutine
		logLines := make(chan string, 64)
		logErr := make(chan error, 1)

		go func() {
			defer close(logLines)
			// Docker multiplexed stream: 8-byte header + payload per frame.
			// Header: [type(1)][0][0][0][size(4 big-endian)]
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
					// Stream ended; check for error
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

// GetStructuredLogs returns parsed, structured log entries for a container
func GetStructuredLogs(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		service := c.Param("service")
		tail := c.DefaultQuery("tail", "200")
		level := c.DefaultQuery("level", "")

		logger.Info("Getting structured logs", "service", service, "tail", tail)

		entries, err := dockerClient.GetStructuredLogs(service, tail, service)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get structured logs: %v", err),
			})
			return
		}

		// Filter by level if specified
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
