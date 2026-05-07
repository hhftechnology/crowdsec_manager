// Package aggregate turns raw container log text into ready-to-render
// dashboard payloads. The functions here are pure and side-effect-free;
// HTTP handlers wire them up to docker.LogParser output and return the
// result as JSON.
package aggregate

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
)

// Location matches the shape of geoip.Location without importing the
// package — keeps the aggregator decoupled and easy to unit-test.
type Location struct {
	Country string
	Lat     float64
	Lng     float64
}

// GeoLookup is the small interface BucketTraefik / BucketCrowdSec need.
// *geoip.Resolver satisfies it via a thin adapter in the handler.
type GeoLookup interface {
	Lookup(ip string) (Location, bool)
}

// noGeo is the zero-value lookup; never resolves anything.
type noGeo struct{}

func (noGeo) Lookup(string) (Location, bool) { return Location{}, false }

const (
	maxTopIPs            = 20
	maxTopHosts          = 10
	maxTopRouters        = 10
	maxSlowestEndpoints  = 10
	maxTLSVersions       = 5
	maxRecentErrors      = 50
)

// BucketTraefikRaw is a convenience wrapper used by tests and callers
// that have raw log text rather than parsed entries. It also peeks at
// the first non-empty line to detect Traefik's JSON access log format
// and, if found, walks every line as JSON in addition to the usual
// CLF parsing.
func BucketTraefikRaw(rawLogs string, since, now time.Time, rng models.DashboardRange, geo GeoLookup) models.TraefikDashboard {
	lines := strings.Split(rawLogs, "\n")
	jsonRows := make([]traefikJSON, 0, len(lines))
	hasJSON := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var row traefikJSON
		if err := json.Unmarshal([]byte(line), &row); err == nil && row.populated() {
			hasJSON = true
			ts := row.startTime()
			if !ts.IsZero() && (since.IsZero() || !ts.Before(since)) {
				jsonRows = append(jsonRows, row)
			}
		}
	}

	parser := docker.NewLogParser()
	entries := parser.Parse(rawLogs, "traefik")

	if hasJSON {
		return aggregateTraefikJSON(jsonRows, since, now, rng, geo)
	}
	return BucketTraefik(entries, since, now, rng, geo)
}

// BucketTraefik aggregates parsed Traefik CLF entries into a dashboard
// payload. JSON-only widgets are returned empty with Format="clf".
func BucketTraefik(entries []docker.StructuredLogEntry, since, now time.Time, rng models.DashboardRange, geo GeoLookup) models.TraefikDashboard {
	if geo == nil {
		geo = noGeo{}
	}
	out := emptyTraefikDashboard(rng, "clf", now)

	gran := bucketGranularity(rng)
	buckets := map[time.Time]*models.TraefikBucket{}
	statusCounts := map[string]int{}
	methodCounts := map[string]int{}
	ipCounts := map[string]int{}
	var errorRows []models.TraefikRecentError
	errorTotal := 0
	totalRequests := 0

	for _, e := range entries {
		ip := e.Fields["client_ip"]
		statusStr := e.Fields["status"]
		if ip == "" || statusStr == "" {
			continue
		}
		ts := e.Timestamp
		if ts.IsZero() {
			continue
		}
		if !since.IsZero() && ts.Before(since) {
			continue
		}

		statusInt, err := strconv.Atoi(statusStr)
		if err != nil {
			continue
		}

		totalRequests++
		ipCounts[ip]++
		statusCounts[statusStr]++
		method := extractCLFMethod(e.Message)
		if method != "" {
			methodCounts[method]++
		}

		bucketKey := ts.Truncate(gran).UTC()
		b, ok := buckets[bucketKey]
		if !ok {
			b = &models.TraefikBucket{T: bucketKey.Format(time.RFC3339)}
			buckets[bucketKey] = b
		}
		b.Total++
		switch statusInt / 100 {
		case 2:
			b.C2xx++
		case 3:
			b.C3xx++
		case 4:
			b.C4xx++
			errorTotal++
		case 5:
			b.C5xx++
			errorTotal++
		}

		if statusInt >= 400 {
			path := extractCLFPath(e.Message)
			errorRows = append(errorRows, models.TraefikRecentError{
				T:      ts.UTC().Format(time.RFC3339),
				IP:     ip,
				Method: method,
				Path:   path,
				Status: statusInt,
			})
		}
	}

	out.TotalRequests = totalRequests
	out.UniqueIPs = len(ipCounts)
	if totalRequests > 0 {
		out.ErrorRate = float64(errorTotal) / float64(totalRequests)
	}

	out.Series = sortedBuckets(buckets)
	out.StatusCodes = topNameValues(statusCounts, 0)
	out.Methods = topNameValues(methodCounts, 0)
	out.TopIPs = topIPs(ipCounts, geo, maxTopIPs)
	out.RecentErrors = sortedRecentErrors(errorRows, maxRecentErrors)

	return out
}

func aggregateTraefikJSON(rows []traefikJSON, since, now time.Time, rng models.DashboardRange, geo GeoLookup) models.TraefikDashboard {
	if geo == nil {
		geo = noGeo{}
	}
	out := emptyTraefikDashboard(rng, "json", now)

	gran := bucketGranularity(rng)
	buckets := map[time.Time]*models.TraefikBucket{}
	statusCounts := map[string]int{}
	methodCounts := map[string]int{}
	hostCounts := map[string]int{}
	routerCounts := map[string]int{}
	tlsCounts := map[string]int{}
	ipCounts := map[string]int{}
	endpointMaxMs := map[string]int{}

	var errorRows []models.TraefikRecentError
	errorTotal := 0
	totalRequests := 0
	var totalDurationNs int64

	for _, row := range rows {
		ts := row.startTime()
		if ts.IsZero() {
			continue
		}
		ip := row.ClientHost
		if ip == "" {
			continue
		}
		totalRequests++
		ipCounts[ip]++
		statusStr := strconv.Itoa(row.DownstreamStatus)
		statusCounts[statusStr]++
		if row.RequestMethod != "" {
			methodCounts[row.RequestMethod]++
		}
		if row.RequestHost != "" {
			hostCounts[row.RequestHost]++
		}
		if row.RouterName != "" {
			routerCounts[row.RouterName]++
		}
		if row.TLSVersion != "" {
			tlsCounts[row.TLSVersion]++
		}
		totalDurationNs += row.Duration

		key := ts.Truncate(gran).UTC()
		b, ok := buckets[key]
		if !ok {
			b = &models.TraefikBucket{T: key.Format(time.RFC3339)}
			buckets[key] = b
		}
		b.Total++
		switch row.DownstreamStatus / 100 {
		case 2:
			b.C2xx++
		case 3:
			b.C3xx++
		case 4:
			b.C4xx++
			errorTotal++
		case 5:
			b.C5xx++
			errorTotal++
		}

		durationMs := int(row.Duration / int64(time.Millisecond))
		path := row.RequestPath
		if path != "" {
			if cur, ok := endpointMaxMs[path]; !ok || durationMs > cur {
				endpointMaxMs[path] = durationMs
			}
		}

		if row.DownstreamStatus >= 400 {
			errorRows = append(errorRows, models.TraefikRecentError{
				T:          ts.UTC().Format(time.RFC3339),
				IP:         ip,
				Method:     row.RequestMethod,
				Path:       row.RequestPath,
				Status:     row.DownstreamStatus,
				DurationMs: int64(durationMs),
			})
		}
	}

	out.TotalRequests = totalRequests
	out.UniqueIPs = len(ipCounts)
	if totalRequests > 0 {
		out.ErrorRate = float64(errorTotal) / float64(totalRequests)
		avgMs := float64(totalDurationNs) / float64(totalRequests) / float64(time.Millisecond)
		out.AvgDurationMs = &avgMs
	}

	out.Series = sortedBuckets(buckets)
	out.StatusCodes = topNameValues(statusCounts, 0)
	out.Methods = topNameValues(methodCounts, 0)
	out.TopHosts = topNameValues(hostCounts, maxTopHosts)
	out.TopRouters = topNameValues(routerCounts, maxTopRouters)
	out.TLSVersions = topNameValues(tlsCounts, maxTLSVersions)
	out.SlowestEndpoints = topNameValues(endpointMaxMs, maxSlowestEndpoints)
	out.TopIPs = topIPs(ipCounts, geo, maxTopIPs)
	out.RecentErrors = sortedRecentErrors(errorRows, maxRecentErrors)

	return out
}

type traefikJSON struct {
	ClientHost       string `json:"ClientHost"`
	DownstreamStatus int    `json:"DownstreamStatus"`
	RequestMethod    string `json:"RequestMethod"`
	RequestHost      string `json:"RequestHost"`
	RequestPath      string `json:"RequestPath"`
	RouterName       string `json:"RouterName"`
	Duration         int64  `json:"Duration"` // nanoseconds (Traefik convention)
	StartUTC         string `json:"StartUTC"`
	StartLocal       string `json:"StartLocal"`
	TLSVersion       string `json:"TLSVersion"`
}

func (r traefikJSON) populated() bool {
	return r.ClientHost != "" || r.DownstreamStatus != 0 || r.RequestMethod != ""
}

func (r traefikJSON) startTime() time.Time {
	if r.StartUTC != "" {
		if t, err := time.Parse(time.RFC3339Nano, r.StartUTC); err == nil {
			return t
		}
		if t, err := time.Parse(time.RFC3339, r.StartUTC); err == nil {
			return t
		}
	}
	if r.StartLocal != "" {
		if t, err := time.Parse(time.RFC3339Nano, r.StartLocal); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func emptyTraefikDashboard(rng models.DashboardRange, format string, now time.Time) models.TraefikDashboard {
	return models.TraefikDashboard{
		Range:            rng,
		Format:           format,
		GeneratedAt:      now.UTC().Format(time.RFC3339),
		Series:           []models.TraefikBucket{},
		StatusCodes:      []models.NameValue{},
		Methods:          []models.NameValue{},
		TopIPs:           []models.IPStat{},
		TopHosts:         []models.NameValue{},
		TopRouters:       []models.NameValue{},
		SlowestEndpoints: []models.NameValue{},
		TLSVersions:      []models.NameValue{},
		RecentErrors:     []models.TraefikRecentError{},
	}
}

func bucketGranularity(rng models.DashboardRange) time.Duration {
	switch rng {
	case models.Range5m:
		return 15 * time.Second
	case models.Range1h:
		return time.Minute
	case models.Range6h:
		return 5 * time.Minute
	case models.Range24h:
		return time.Hour
	default:
		return time.Minute
	}
}

func sortedBuckets(buckets map[time.Time]*models.TraefikBucket) []models.TraefikBucket {
	keys := make([]time.Time, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Before(keys[j]) })
	out := make([]models.TraefikBucket, 0, len(keys))
	for _, k := range keys {
		out = append(out, *buckets[k])
	}
	return out
}

func topNameValues(counts map[string]int, limit int) []models.NameValue {
	out := make([]models.NameValue, 0, len(counts))
	for k, v := range counts {
		out = append(out, models.NameValue{Name: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Name < out[j].Name
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func topIPs(counts map[string]int, geo GeoLookup, limit int) []models.IPStat {
	out := make([]models.IPStat, 0, len(counts))
	for ip, count := range counts {
		row := models.IPStat{IP: ip, Count: count}
		if loc, ok := geo.Lookup(ip); ok {
			row.Country = loc.Country
			row.Lat = loc.Lat
			row.Lng = loc.Lng
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].IP < out[j].IP
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func sortedRecentErrors(rows []models.TraefikRecentError, limit int) []models.TraefikRecentError {
	if rows == nil {
		return []models.TraefikRecentError{}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].T > rows[j].T })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// extractCLFMethod pulls METHOD from a CLF request line e.g. `GET /a HTTP/1.1`.
func extractCLFMethod(message string) string {
	if message == "" {
		return ""
	}
	if i := strings.IndexByte(message, ' '); i > 0 {
		return message[:i]
	}
	return ""
}

// extractCLFPath pulls the path from a CLF request line.
func extractCLFPath(message string) string {
	parts := strings.SplitN(message, " ", 3)
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}
