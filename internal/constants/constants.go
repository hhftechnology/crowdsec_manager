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

// CloudflareTurnstileScript is the Cloudflare Turnstile captcha JavaScript URL
const CloudflareTurnstileScript = "https://challenges.cloudflare.com/turnstile/v0/api.js"

// GeoapifyMapURLPattern is the static map URL template for Discord notification embeds
const GeoapifyMapURLPattern = "https://maps.geoapify.com/v1/staticmap?style=osm-bright-grey&width=600&height=400&center=lonlat:{{$alert.Source.Longitude}},{{$alert.Source.Latitude}}&zoom=8.1848&marker=lonlat:{{$alert.Source.Longitude}},{{$alert.Source.Latitude}};type:awesome;color:%23655e90;size:large;icon:industry|lonlat:{{$alert.Source.Longitude}},{{$alert.Source.Latitude}};type:material;color:%23ff3421;icontype:awesome&scaleFactor=2&apiKey={{env \"GEOAPIFY_API_KEY\"}}"

// DefaultPingInterval is the default interval for WebSocket ping messages
const DefaultPingInterval = 30 * time.Second

// DefaultReadDeadline is the default read deadline for WebSocket connections
const DefaultReadDeadline = 30 * time.Minute

// CrowdSecConfigSubdir is the subdirectory name for CrowdSec configuration within the config directory
const CrowdSecConfigSubdir = "crowdsec"

// DefaultWebSocketBufferSize is the default buffer size for WebSocket read/write operations
const DefaultWebSocketBufferSize = 4096

// ExternalHTTPTimeout is the timeout for outbound HTTP requests (IP lookups, etc.)
const ExternalHTTPTimeout = 10 * time.Second

// ExternalHTTPClient is a shared HTTP client with a sensible timeout.
// Use this instead of http.Get() to prevent goroutine leaks.
var ExternalHTTPClient = &http.Client{
	Timeout: ExternalHTTPTimeout,
}
