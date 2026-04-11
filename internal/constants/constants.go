package constants

import (
	"net/http"
	"time"
)

// ExternalIPServices lists public IP lookup services used for reliability via fallback
var ExternalIPServices = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
}

// DefaultPingInterval is the default interval for WebSocket ping messages
const DefaultPingInterval = 30 * time.Second

// DefaultReadDeadline is the default read deadline for WebSocket connections
const DefaultReadDeadline = 30 * time.Minute

// CrowdSecConfigSubdir is the subdirectory name for CrowdSec configuration within the config directory
const CrowdSecConfigSubdir = "crowdsec"

// DefaultWebSocketBufferSize is the default buffer size for WebSocket read/write operations
const DefaultWebSocketBufferSize = 4096

// MaxListLimit is the hard safety cap for cscli list commands.
// Even when the user sets limit=0 (unlimited), we enforce this cap to prevent
// memory exhaustion from very large result sets (e.g. 10,000+ decisions/alerts).
// Matches CrowdSec's default DB retention of 5,000 items.
const MaxListLimit = 5000

// ExecCommandTimeout is the timeout for cscli commands executed inside containers.
// Prevents hanging if cscli takes too long on large datasets.
const ExecCommandTimeout = 60 * time.Second

// ExternalHTTPTimeout is the timeout for outbound HTTP requests (IP lookups, etc.)
const ExternalHTTPTimeout = 10 * time.Second

// ExternalHTTPClient is a shared HTTP client with a sensible timeout.
// Use this instead of http.Get() to prevent goroutine leaks.
var ExternalHTTPClient = &http.Client{
	Timeout: ExternalHTTPTimeout,
}
