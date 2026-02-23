package handlers

import (
	"crowdsec-manager/internal/messaging"

	"github.com/gin-gonic/gin"
)

// EventsWebSocket returns a handler that upgrades to WebSocket for real-time events
func EventsWebSocket(hub *messaging.Hub) gin.HandlerFunc {
	return hub.HandleWebSocket()
}
