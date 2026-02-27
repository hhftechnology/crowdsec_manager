package messaging

import "time"

// Subject constants for NATS pub/sub
const (
	SubjectDecisionAdded   = "crowdsec.decision.added"
	SubjectDecisionRemoved = "crowdsec.decision.removed"
	SubjectContainerState  = "docker.container.state"
	SubjectSystemEvent     = "system.event"
)

// Event is the envelope for all events published through the messaging system
type Event struct {
	ID        string      `json:"id"`
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	HostID    string      `json:"host_id,omitempty"`
	Payload   interface{} `json:"payload"`
}

// DecisionEvent carries decision add/remove information
type DecisionEvent struct {
	IP       string `json:"ip,omitempty"`
	Range    string `json:"range,omitempty"`
	Type     string `json:"type"`
	Duration string `json:"duration,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Action   string `json:"action"` // "added" or "removed"
}

// ContainerStateEvent carries container start/stop/restart events
type ContainerStateEvent struct {
	Container string `json:"container"`
	Action    string `json:"action"` // "start", "stop", "restart"
	Success   bool   `json:"success"`
}
