// Package geoip wraps a MaxMind GeoLite2 reader and exposes a thin
// Resolver interface used by the dashboard aggregators. When no database
// is available (file missing or open error) Open returns a no-op resolver
// so the rest of the application keeps working without country/coordinate
// data.
package geoip

import (
	"errors"
	"net"
	"os"
	"sync"

	"github.com/oschwald/geoip2-golang"

	"crowdsec-manager/internal/logger"
)

// Location is the subset of GeoLite2 fields the dashboards need.
type Location struct {
	Country string  `json:"country,omitempty"`
	Lat     float64 `json:"lat,omitempty"`
	Lng     float64 `json:"lng,omitempty"`
}

// Resolver looks up an IP address. The zero value (and a Resolver returned
// by Open when the database is missing) returns ok=false for every lookup.
type Resolver struct {
	reader *geoip2.Reader
	mu     sync.RWMutex
	cache  map[string]Location // bounded by maxCacheEntries
}

const maxCacheEntries = 4096

// ErrNoDatabase indicates the configured database file does not exist.
// Open returns a usable no-op resolver alongside this error so callers can
// log a warning without aborting startup.
var ErrNoDatabase = errors.New("geoip: database not configured or missing")

// Open returns a Resolver backed by the .mmdb file at path. If path is empty
// or the file does not exist, a no-op resolver is returned along with
// ErrNoDatabase. Other errors (corrupt database) are also returned with a
// no-op resolver so the server still starts.
func Open(path string) (*Resolver, error) {
	if path == "" {
		return &Resolver{cache: map[string]Location{}}, ErrNoDatabase
	}
	if _, err := os.Stat(path); err != nil {
		return &Resolver{cache: map[string]Location{}}, ErrNoDatabase
	}
	r, err := geoip2.Open(path)
	if err != nil {
		return &Resolver{cache: map[string]Location{}}, err
	}
	return &Resolver{reader: r, cache: map[string]Location{}}, nil
}

// Close releases the underlying reader. Safe to call on a no-op resolver.
func (r *Resolver) Close() error {
	if r == nil || r.reader == nil {
		return nil
	}
	return r.reader.Close()
}

// Lookup returns location data for ip. It returns ok=false when the
// database is unavailable, the ip is private/loopback, or the lookup
// produces no city record.
func (r *Resolver) Lookup(ip string) (Location, bool) {
	if r == nil || ip == "" {
		return Location{}, false
	}

	r.mu.RLock()
	if loc, ok := r.cache[ip]; ok {
		r.mu.RUnlock()
		return loc, loc.Country != ""
	}
	r.mu.RUnlock()

	parsed := net.ParseIP(ip)
	if parsed == nil || isPrivate(parsed) {
		r.cacheStore(ip, Location{})
		return Location{}, false
	}

	if r.reader == nil {
		return Location{}, false
	}

	city, err := r.reader.City(parsed)
	if err != nil || city == nil {
		r.cacheStore(ip, Location{})
		return Location{}, false
	}

	loc := Location{
		Country: city.Country.IsoCode,
		Lat:     city.Location.Latitude,
		Lng:     city.Location.Longitude,
	}
	r.cacheStore(ip, loc)
	return loc, loc.Country != ""
}

func (r *Resolver) cacheStore(ip string, loc Location) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= maxCacheEntries {
		for k := range r.cache {
			delete(r.cache, k)
			break
		}
	}
	r.cache[ip] = loc
}

// LogStartupStatus emits a single info/warn line summarising the resolver
// state. Call once after Open in main.
func LogStartupStatus(path string, openErr error) {
	switch {
	case errors.Is(openErr, ErrNoDatabase):
		logger.Warn("GeoIP database not found; country/coords will be empty", "path", path)
	case openErr != nil:
		logger.Warn("GeoIP database failed to open; country/coords will be empty", "path", path, "error", openErr)
	default:
		logger.Info("GeoIP database loaded", "path", path)
	}
}

func isPrivate(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, cidr := range privateCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

var privateCIDRs = func() []*net.IPNet {
	blocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}
	out := make([]*net.IPNet, 0, len(blocks))
	for _, b := range blocks {
		_, n, err := net.ParseCIDR(b)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}()
