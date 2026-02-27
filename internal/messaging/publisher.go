package messaging

import (
	"time"

	"crowdsec-manager/internal/logger"

	"github.com/google/uuid"
)

// Publisher is a nil-safe wrapper around Client for publishing typed events.
// All methods are safe to call when Publisher or its client is nil (no-op).
type Publisher struct {
	client *Client
}

// NewPublisher creates a Publisher. Pass nil for disabled messaging.
func NewPublisher(client *Client) *Publisher {
	return &Publisher{client: client}
}

// PublishDecisionAdded publishes a decision-added event
func (p *Publisher) PublishDecisionAdded(ip, decisionType, duration, reason string) {
	if p == nil || p.client == nil {
		return
	}

	event := Event{
		ID:        uuid.NewString(),
		Type:      SubjectDecisionAdded,
		Timestamp: time.Now(),
		Payload: DecisionEvent{
			IP:       ip,
			Type:     decisionType,
			Duration: duration,
			Reason:   reason,
			Action:   "added",
		},
	}

	if err := p.client.Publish(SubjectDecisionAdded, event); err != nil {
		logger.Warn("Failed to publish decision added event", "error", err)
	}
}

// PublishDecisionRemoved publishes a decision-removed event
func (p *Publisher) PublishDecisionRemoved(ip, decisionType string) {
	if p == nil || p.client == nil {
		return
	}

	event := Event{
		ID:        uuid.NewString(),
		Type:      SubjectDecisionRemoved,
		Timestamp: time.Now(),
		Payload: DecisionEvent{
			IP:     ip,
			Type:   decisionType,
			Action: "removed",
		},
	}

	if err := p.client.Publish(SubjectDecisionRemoved, event); err != nil {
		logger.Warn("Failed to publish decision removed event", "error", err)
	}
}

// PublishContainerState publishes a container state change event
func (p *Publisher) PublishContainerState(container, action string, success bool) {
	if p == nil || p.client == nil {
		return
	}

	event := Event{
		ID:        uuid.NewString(),
		Type:      SubjectContainerState,
		Timestamp: time.Now(),
		Payload: ContainerStateEvent{
			Container: container,
			Action:    action,
			Success:   success,
		},
	}

	if err := p.client.Publish(SubjectContainerState, event); err != nil {
		logger.Warn("Failed to publish container state event", "error", err)
	}
}
