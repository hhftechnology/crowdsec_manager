package messaging

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"crowdsec-manager/internal/logger"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// wsClient represents a connected WebSocket client
type wsClient struct {
	conn    *websocket.Conn
	send    chan []byte
	subjects map[string]bool // subjects this client subscribes to
	mu      sync.RWMutex
}

// Hub manages WebSocket client connections and broadcasts NATS events
type Hub struct {
	clients    map[*wsClient]bool
	broadcast  chan []byte
	register   chan *wsClient
	unregister chan *wsClient
	stop       chan struct{}
	mu         sync.RWMutex
}

// NewHub creates a new WebSocket hub
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*wsClient]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *wsClient),
		unregister: make(chan *wsClient),
		stop:       make(chan struct{}),
	}
}

// Run starts the hub's event loop
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					h.mu.RUnlock()
					h.mu.Lock()
					delete(h.clients, client)
					close(client.send)
					h.mu.Unlock()
					h.mu.RLock()
				}
			}
			h.mu.RUnlock()

		case <-h.stop:
			h.mu.Lock()
			for client := range h.clients {
				close(client.send)
				delete(h.clients, client)
			}
			h.mu.Unlock()
			return
		}
	}
}

// Stop shuts down the hub
func (h *Hub) Stop() {
	close(h.stop)
}

// Broadcast sends a message to all connected WebSocket clients
func (h *Hub) Broadcast(event Event) {
	data, err := json.Marshal(event)
	if err != nil {
		logger.Warn("Failed to marshal event for broadcast", "error", err)
		return
	}

	select {
	case h.broadcast <- data:
	default:
		logger.Warn("Hub broadcast channel full, dropping event")
	}
}

// HandleWebSocket returns a Gin handler that upgrades to WebSocket
func (h *Hub) HandleWebSocket() gin.HandlerFunc {
	return func(c *gin.Context) {
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			logger.Error("WebSocket upgrade failed", "error", err)
			return
		}

		client := &wsClient{
			conn:     conn,
			send:     make(chan []byte, 256),
			subjects: make(map[string]bool),
		}

		h.register <- client

		go client.writePump()
		go client.readPump(h)
	}
}

// readPump reads messages from the WebSocket client (subscription requests)
func (c *wsClient) readPump(hub *Hub) {
	defer func() {
		hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				logger.Debug("WebSocket read error", "error", err)
			}
			break
		}

		// Parse subscription requests: {"subscribe": ["crowdsec.>", "docker.>"]}
		var req struct {
			Subscribe []string `json:"subscribe"`
		}
		if err := json.Unmarshal(message, &req); err == nil && len(req.Subscribe) > 0 {
			c.mu.Lock()
			for _, s := range req.Subscribe {
				c.subjects[s] = true
			}
			c.mu.Unlock()
		}
	}
}

// writePump sends messages to the WebSocket client
func (c *wsClient) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
