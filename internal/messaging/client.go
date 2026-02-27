package messaging

import (
	"encoding/json"
	"fmt"
	"time"

	"crowdsec-manager/internal/logger"

	"github.com/nats-io/nats.go"
)

// Client wraps a NATS connection with JetStream support
type Client struct {
	conn *nats.Conn
	js   nats.JetStreamContext
}

// NewClient connects to a NATS server and initializes JetStream streams.
// Returns nil, nil when URL is empty (graceful no-op for disabled messaging).
func NewClient(url, token string) (*Client, error) {
	if url == "" {
		return nil, nil
	}

	opts := []nats.Option{
		nats.Name("crowdsec-manager"),
		nats.ReconnectWait(2 * time.Second),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				logger.Warn("NATS disconnected", "error", err)
			}
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			logger.Info("NATS reconnected")
		}),
	}

	if token != "" {
		opts = append(opts, nats.Token(token))
	}

	conn, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS at %s: %w", url, err)
	}

	js, err := conn.JetStream()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to initialize JetStream: %w", err)
	}

	c := &Client{conn: conn, js: js}

	// Create streams if they don't exist
	if err := c.ensureStreams(); err != nil {
		logger.Warn("Failed to create NATS streams (may already exist)", "error", err)
	}

	return c, nil
}

// ensureStreams creates the required JetStream streams
func (c *Client) ensureStreams() error {
	streams := []struct {
		name     string
		subjects []string
	}{
		{"CROWDSEC", []string{"crowdsec.>"}},
		{"DOCKER", []string{"docker.>"}},
		{"SYSTEM", []string{"system.>"}},
	}

	for _, s := range streams {
		_, err := c.js.AddStream(&nats.StreamConfig{
			Name:      s.name,
			Subjects:  s.subjects,
			Retention: nats.InterestPolicy,
			MaxAge:    24 * time.Hour,
		})
		if err != nil {
			// Stream may already exist, try to update
			_, updateErr := c.js.UpdateStream(&nats.StreamConfig{
				Name:      s.name,
				Subjects:  s.subjects,
				Retention: nats.InterestPolicy,
				MaxAge:    24 * time.Hour,
			})
			if updateErr != nil {
				return fmt.Errorf("stream %s: create=%w, update=%v", s.name, err, updateErr)
			}
		}
	}

	return nil
}

// Publish publishes an event to the given subject
func (c *Client) Publish(subject string, event Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	_, err = c.js.Publish(subject, data)
	if err != nil {
		return fmt.Errorf("failed to publish to %s: %w", subject, err)
	}
	return nil
}

// Subscribe subscribes to a subject pattern and calls the handler for each message
func (c *Client) Subscribe(subject string, handler func(Event)) (*nats.Subscription, error) {
	return c.conn.Subscribe(subject, func(msg *nats.Msg) {
		var event Event
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			logger.Warn("Failed to unmarshal NATS event", "subject", subject, "error", err)
			return
		}
		handler(event)
	})
}

// Close closes the NATS connection
func (c *Client) Close() {
	if c != nil && c.conn != nil {
		c.conn.Drain()
	}
}
