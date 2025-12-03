package handlers

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
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

// StreamLogs streams logs via WebSocket
func StreamLogs(dockerClient *docker.Client) gin.HandlerFunc {
	var upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	return func(c *gin.Context) {
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

		// Start ping ticker
		pingTicker := time.NewTicker(30 * time.Second)
		defer pingTicker.Stop()

		// Stream logs in real-time
		logTicker := time.NewTicker(500 * time.Millisecond)
		defer logTicker.Stop()

		done := make(chan struct{})

		// Track last sent log lines to avoid sending duplicates
		var lastSentHash string
		lastLogLines := make([]string, 0)

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

		for {
			select {
			case <-done:
				return
			case <-pingTicker.C:
				if err := ws.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
					logger.Debug("WebSocket ping error", "error", err)
					return
				}
			case <-logTicker.C:
				// Check if container is running before attempting to get logs
				isRunning, err := dockerClient.IsContainerRunning(service)
				if err != nil {
					// Only send error once per unique error
					errorMsg := fmt.Sprintf("Error checking container status: %v", err)
					if lastSentHash != errorMsg {
						ws.WriteMessage(websocket.TextMessage, []byte(errorMsg))
						lastSentHash = errorMsg
					}
					continue
				}

				if !isRunning {
					// Only send status message once
					statusMsg := fmt.Sprintf("Container '%s' is not running (restarting or stopped)", service)
					if lastSentHash != statusMsg {
						ws.WriteMessage(websocket.TextMessage, []byte(statusMsg))
						lastSentHash = statusMsg
					}
					continue
				}

				logs, err := dockerClient.GetContainerLogs(service, "100")
				if err != nil {
					errorMsg := fmt.Sprintf("Error fetching logs: %v", err)
					if lastSentHash != errorMsg {
						ws.WriteMessage(websocket.TextMessage, []byte(errorMsg))
						lastSentHash = errorMsg
					}
					continue
				}

				// Clean the logs
				logs = strings.TrimSpace(logs)
				if logs == "" {
					continue // Skip empty logs
				}

				// Split logs into lines
				currentLines := strings.Split(logs, "\n")
				if len(currentLines) == 0 {
					continue
				}

				// Calculate hash of last few lines to detect if content changed
				var currentHash string
				if len(currentLines) > 0 {
					// Use last 10 lines for hash comparison
					lastLines := currentLines
					if len(lastLines) > 10 {
						lastLines = lastLines[len(lastLines)-10:]
					}
					currentHash = strings.Join(lastLines, "\n")
				}

				// Only send new lines if content has changed
				if currentHash != lastSentHash && currentHash != "" {
					// Find new lines that weren't in the previous batch
					var newLines []string
					if len(lastLogLines) == 0 {
						// First batch, send all lines
						newLines = currentLines
					} else {
						// Find lines that are new compared to last batch
						lastLineMap := make(map[string]bool)
						for _, line := range lastLogLines {
							lastLineMap[line] = true
						}
						for _, line := range currentLines {
							if !lastLineMap[line] {
								newLines = append(newLines, line)
							}
						}
					}

					// Only send if there are actual new lines
					if len(newLines) > 0 {
						newContent := strings.Join(newLines, "\n")
						if err := ws.WriteMessage(websocket.TextMessage, []byte(newContent)); err != nil {
							logger.Debug("WebSocket write error", "error", err)
							return
						}
						lastSentHash = currentHash
						lastLogLines = currentLines
						// Keep only last 50 lines to avoid memory growth
						if len(lastLogLines) > 50 {
							lastLogLines = lastLogLines[len(lastLogLines)-50:]
						}
					}
				}
			}
		}
	}
}

// analyzeLogs performs log analysis and returns statistics
func analyzeLogs(logs string) models.LogStats {
	lines := strings.Split(logs, "\n")

	stats := models.LogStats{
		TotalLines:   len(lines),
		TopIPs:       []models.IPCount{},
		StatusCodes:  make(map[string]int),
		HTTPMethods:  make(map[string]int),
		ErrorEntries: []models.LogEntry{},
	}

	ipMap := make(map[string]int)
	ipRegex := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	statusRegex := regexp.MustCompile(`\s(2\d{2}|3\d{2}|4\d{2}|5\d{2})\s`)
	methodRegex := regexp.MustCompile(`"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)`)

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Extract IPs
		if ips := ipRegex.FindAllString(line, -1); len(ips) > 0 {
			for _, ip := range ips {
				ipMap[ip]++
			}
		}

		// Extract status codes
		if matches := statusRegex.FindStringSubmatch(line); len(matches) > 1 {
			stats.StatusCodes[matches[1]]++
		}

		// Extract HTTP methods
		if matches := methodRegex.FindStringSubmatch(line); len(matches) > 1 {
			stats.HTTPMethods[matches[1]]++
		}

		// Collect error entries
		if strings.Contains(strings.ToLower(line), "error") ||
			strings.Contains(line, "5") && statusRegex.MatchString(line) {
			stats.ErrorEntries = append(stats.ErrorEntries, models.LogEntry{
				Timestamp: time.Now(),
				Level:     "error",
				Service:   "traefik",
				Message:   line,
			})
		}
	}

	// Convert IP map to sorted slice
	for ip, count := range ipMap {
		stats.TopIPs = append(stats.TopIPs, models.IPCount{
			IP:    ip,
			Count: count,
		})
	}
	sort.Slice(stats.TopIPs, func(i, j int) bool {
		return stats.TopIPs[i].Count > stats.TopIPs[j].Count
	})

	// Keep only top 10 IPs
	if len(stats.TopIPs) > 10 {
		stats.TopIPs = stats.TopIPs[:10]
	}

	// Keep only last 20 error entries
	if len(stats.ErrorEntries) > 20 {
		stats.ErrorEntries = stats.ErrorEntries[len(stats.ErrorEntries)-20:]
	}

	return stats
}
