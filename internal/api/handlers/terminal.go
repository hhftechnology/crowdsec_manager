package handlers

import (
	"io"
	"net/http"
	"strings"
	"time"

	"crowdsec-manager/internal/api/middleware"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

func terminalUpgrader(allowedOrigins []string) websocket.Upgrader {
	return websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return middleware.OriginPermitted(r.Header.Get("Origin"), r.Host, allowedOrigins)
		},
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
	}
}

// TerminalSession upgrades to WebSocket and creates an interactive terminal session.
// allowedOrigins is the extra-origin list from CORS_ALLOWED_ORIGINS. Requests
// whose Origin names some other host are rejected before a shell is started.
func TerminalSession(dockerClient *docker.Client, allowedOrigins []string) gin.HandlerFunc {
	upgrader := terminalUpgrader(allowedOrigins)
	return func(c *gin.Context) {
		if !middleware.OriginPermitted(c.GetHeader("Origin"), c.Request.Host, allowedOrigins) {
			c.AbortWithStatusJSON(http.StatusForbidden, models.Response{
				Success: false,
				Error:   "origin not allowed",
			})
			return
		}

		dockerClient = resolveDockerClient(c, dockerClient)
		containerName := c.Param("container")
		if containerName == "" {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "container name required"})
			return
		}

		// Reject path traversal or shell metacharacters in container name
		if strings.ContainsAny(containerName, "/\\;|&$`'\"") {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "invalid container name"})
			return
		}

		// Verify container is running
		running, err := dockerClient.IsContainerRunning(containerName)
		if err != nil || !running {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "container is not running"})
			return
		}

		ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			logger.Error("Terminal WebSocket upgrade failed", "error", err)
			return
		}
		defer ws.Close()

		// Create interactive exec session
		session, err := docker.ExecInteractive(dockerClient, containerName, []string{"/bin/sh"}, nil)
		if err != nil {
			logger.Error("Failed to create exec session", "error", err, "container", containerName)
			ws.WriteMessage(websocket.TextMessage, []byte("Error: "+err.Error()))
			return
		}
		defer session.Close()

		logger.Info("Terminal session started", "container", containerName)

		// Relay stdout from container to WebSocket
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := session.Read(buf)
				if n > 0 {
					if writeErr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); writeErr != nil {
						return
					}
				}
				if err != nil {
					if err != io.EOF {
						logger.Debug("Terminal read error", "error", err)
					}
					ws.WriteMessage(websocket.CloseMessage,
						websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session ended"))
					return
				}
			}
		}()

		// Relay stdin from WebSocket to container
		ws.SetReadDeadline(time.Now().Add(30 * time.Minute))
		ws.SetPongHandler(func(string) error {
			ws.SetReadDeadline(time.Now().Add(30 * time.Minute))
			return nil
		})

		for {
			msgType, data, err := ws.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					logger.Debug("Terminal WebSocket closed", "error", err)
				}
				return
			}

			switch msgType {
			case websocket.TextMessage, websocket.BinaryMessage:
				// Check for resize message (JSON: {"type":"resize","cols":80,"rows":24})
				if len(data) > 0 && data[0] == '{' {
					if handled := session.HandleResize(data); handled {
						continue
					}
				}
				if _, err := session.Write(data); err != nil {
					logger.Debug("Terminal write error", "error", err)
					return
				}
			}
		}
	}
}
