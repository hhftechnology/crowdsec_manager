// Package aggregate turns raw container log text into ready-to-render
// dashboard payloads. The functions here are pure and side-effect-free;
// HTTP handlers wire them up to docker.LogParser output and return the
// result as JSON.
package aggregate

import (
	"bufio"
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
	scanner := bufio.NewScanner(strings.NewReader(rawLogs))
	jsonRows := make([]traefikJSON, 0, 1000) // Initial capacity hint
	hasJSON := false

	for scanner.Scan() {
		line := scanner.Text()
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

	if hasJSON {
		return aggregateTraefikJSON(jsonRows, since, now, rng, geo)
	}

	parser := docker.NewLogParser()
	entries := parser.Parse(rawLogs, "traefik")

	return BucketTraefik(entries, since, now, rng, geo)
}

// BucketTraefik aggregates parsed Traefik CLF entries into a dashboard
// payload. JSON-only widgets are returned empty with Format="clf".
func BucketTraefik(entries []docker.StructuredLogEntry, since, now time.Time, rng models.DashboardRange, geo GeoLookup) models.TraefikDashboard {
	if geo == nil {
		geo = noGeo{}
	}
	out := emptyTraefikDashboard(rng, "clf", now)

	var minTs, maxTs time.Time
	for _, e := range entries {
		if e.Timestamp.IsZero() {
			continue
		}
		if !since.IsZero() && e.Timestamp.Before(since) {
			continue
		}
		if minTs.IsZero() || e.Timestamp.Before(minTs) {
			minTs = e.Timestamp
		}
		if maxTs.IsZero() || e.Timestamp.After(maxTs) {
			maxTs = e.Timestamp
		}
	}

	gran := bucketGranularity(rng)
	if (rng == models.RangeAll || rng == models.Range7d) && !minTs.IsZero() && !maxTs.IsZero() {
		gran = calculateDynamicGranularity(maxTs.Sub(minTs))
	}

	buckets := map[time.Time]*models.TraefikBucket{}
	if !minTs.IsZero() && !maxTs.IsZero() {
		start := minTs.Truncate(gran).UTC()
		end := maxTs.Truncate(gran).UTC()
		for t := start; !t.After(end); t = t.Add(gran) {
			buckets[t] = &models.TraefikBucket{T: t.Format(time.RFC3339)}
		}
	}
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
	out.System = GetSystemStats()

	return out
}

type serviceAgg struct {
	count    int
	totalDur int64
	errors   int
}

type pathAgg struct {
	count    int
	totalDur int64
	method   string
}

type routerAgg struct {
	count    int
	totalDur int64
	service  string
}

func aggregateTraefikJSON(rows []traefikJSON, since, now time.Time, rng models.DashboardRange, geo GeoLookup) models.TraefikDashboard {
	if geo == nil {
		geo = noGeo{}
	}
	out := emptyTraefikDashboard(rng, "json", now)

	var minTs, maxTs time.Time
	for _, row := range rows {
		ts := row.startTime()
		if ts.IsZero() {
			continue
		}
		if minTs.IsZero() || ts.Before(minTs) {
			minTs = ts
		}
		if maxTs.IsZero() || ts.After(maxTs) {
			maxTs = ts
		}
	}

	gran := bucketGranularity(rng)
	if (rng == models.RangeAll || rng == models.Range7d) && !minTs.IsZero() && !maxTs.IsZero() {
		gran = calculateDynamicGranularity(maxTs.Sub(minTs))
	}

	buckets := map[time.Time]*models.TraefikBucket{}
	if !minTs.IsZero() && !maxTs.IsZero() {
		start := minTs.Truncate(gran).UTC()
		end := maxTs.Truncate(gran).UTC()
		for t := start; !t.After(end); t = t.Add(gran) {
			buckets[t] = &models.TraefikBucket{T: t.Format(time.RFC3339)}
		}
	}
	statusCounts := map[string]int{}
	methodCounts := map[string]int{}
	hostCounts := map[string]int{}
	tlsCounts := map[string]int{}
	ipCounts := map[string]int{}
	uaCounts := map[string]int{}
	addrCounts := map[string]int{}
	endpointMaxMs := map[string]int{}

	serviceStats := map[string]*serviceAgg{}
	pathStats := map[string]*pathAgg{}
	routerStats := map[string]*routerAgg{}

	var errorRows []models.TraefikRecentError
	errorTotal := 0
	totalRequests := 0
	var totalDurationNs int64
	durationsMs := make([]float64, 0, len(rows))

	for _, row := range rows {
		ts := row.startTime()
		if ts.IsZero() {
			continue
		}
		ip := row.getIP()
		if ip == "" {
			continue
		}

		method := row.getMethod()
		host := row.getHost()
		path := row.getPath()
		status := row.getStatus()
		duration := row.getDuration()
		router := row.getRouter()
		service := row.getService()
		ua := row.getUA()

		totalRequests++
		ipCounts[ip]++
		totalDurationNs += duration

		if method != "" {
			methodCounts[method]++
		}
		if host != "" {
			hostCounts[host]++
		}
		if router != "" {
			r := routerStats[router]
			if r == nil {
				r = &routerAgg{service: service}
				routerStats[router] = r
			}
			r.count++
			r.totalDur += duration
		}
		if service != "" {
			s := serviceStats[service]
			if s == nil {
				s = &serviceAgg{}
				serviceStats[service] = s
			}
			s.count++
			s.totalDur += duration
			if status >= 400 {
				s.errors++
			}
		}
		if path != "" {
			key := method + ":" + path
			p := pathStats[key]
			if p == nil {
				p = &pathAgg{method: method}
				pathStats[key] = p
			}
			p.count++
			p.totalDur += duration
		}
		if ua != "" {
			uaCounts[ua]++
		}

		addr := row.RequestAddr
		if addr == "" {
			addr = row.Request_Addr
		}
		if addr != "" {
			addrCounts[addr]++
		}
		tls := row.TLSVersion
		if tls == "" {
			tls = row.TLS_Version_Small
		}
		if tls != "" {
			tlsCounts[tls]++
		}

		statusStr := strconv.Itoa(status)
		statusCounts[statusStr]++

		if status >= 400 {
			errorTotal++
		}
		durationsMs = append(durationsMs, float64(duration)/float64(time.Millisecond))

		bucketKey := ts.Truncate(gran).UTC()
		b, ok := buckets[bucketKey]
		if !ok {
			b = &models.TraefikBucket{T: bucketKey.Format(time.RFC3339)}
			buckets[bucketKey] = b
		}
		b.Total++
		switch status / 100 {
		case 2:
			b.C2xx++
		case 3:
			b.C3xx++
		case 4:
			b.C4xx++
		case 5:
			b.C5xx++
		}

		durationMs := int(duration / int64(time.Millisecond))
		if path != "" && !isStreamingPath(path) {
			if cur, ok := endpointMaxMs[path]; !ok || durationMs > cur {
				endpointMaxMs[path] = durationMs
			}
		}

		if status >= 400 {
			errorRows = append(errorRows, models.TraefikRecentError{
				T:          ts.UTC().Format(time.RFC3339),
				IP:         ip,
				Method:     method,
				Path:       path,
				Status:     status,
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

		sort.Float64s(durationsMs)
		p95Idx := int(float64(len(durationsMs)) * 0.95)
		p99Idx := int(float64(len(durationsMs)) * 0.99)

		if p95Idx >= len(durationsMs) {
			p95Idx = len(durationsMs) - 1
		}
		if p95Idx < 0 {
			p95Idx = 0
		}
		if p99Idx >= len(durationsMs) {
			p99Idx = len(durationsMs) - 1
		}
		if p99Idx < 0 {
			p99Idx = 0
		}

		if len(durationsMs) > 0 {
			p95Ms := durationsMs[p95Idx]
			out.P95ResponseTimeMs = &p95Ms
			p99Ms := durationsMs[p99Idx]
			out.P99ResponseTimeMs = &p99Ms
		}
	}

	out.Series = sortedBuckets(buckets)
	out.StatusCodes = topNameValues(statusCounts, 0)
	out.Methods = topNameValues(methodCounts, 0)
	out.TopRouters = sortedRouterDetails(routerStats, maxTopRouters)
	out.TopPaths = sortedPathDetails(pathStats, maxTopRouters)
	out.TopHosts = topNameValues(hostCounts, maxTopHosts)
	out.TopAddresses = topNameValues(addrCounts, maxTopRouters)
	out.UserAgents = topNameValues(uaCounts, 50)
	out.TopServices = sortedServiceDetails(serviceStats, maxTopRouters)
	out.TLSVersions = topNameValues(tlsCounts, maxTLSVersions)
	out.SlowestEndpoints = topNameValues(endpointMaxMs, maxSlowestEndpoints)
	out.TopIPs = topIPs(ipCounts, geo, maxTopIPs)
	out.RecentErrors = sortedRecentErrors(errorRows, maxRecentErrors)
	out.System = GetSystemStats()

	return out
}

func sortedServiceDetails(stats map[string]*serviceAgg, limit int) []models.TraefikServiceDetail {
	out := make([]models.TraefikServiceDetail, 0, len(stats))
	for name, s := range stats {
		avg := 0.0
		if s.count > 0 {
			avg = float64(s.totalDur) / float64(s.count) / float64(time.Millisecond)
		}
		errRate := 0.0
		if s.count > 0 {
			errRate = (float64(s.errors) / float64(s.count)) * 100
		}
		out = append(out, models.TraefikServiceDetail{
			Name:        name,
			Requests:    s.count,
			AvgDuration: avg,
			ErrorRate:   errRate,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Requests > out[j].Requests
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func sortedPathDetails(stats map[string]*pathAgg, limit int) []models.TraefikPathDetail {
	out := make([]models.TraefikPathDetail, 0, len(stats))
	for key, p := range stats {
		// key is Method:Path
		parts := strings.SplitN(key, ":", 2)
		path := key
		if len(parts) == 2 {
			path = parts[1]
		}
		avg := 0.0
		if p.count > 0 {
			avg = float64(p.totalDur) / float64(p.count) / float64(time.Millisecond)
		}
		out = append(out, models.TraefikPathDetail{
			Path:        path,
			Method:      p.method,
			Count:       p.count,
			AvgDuration: avg,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Count > out[j].Count
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func sortedRouterDetails(stats map[string]*routerAgg, limit int) []models.TraefikRouterDetail {
	out := make([]models.TraefikRouterDetail, 0, len(stats))
	for name, r := range stats {
		avg := 0.0
		if r.count > 0 {
			avg = float64(r.totalDur) / float64(r.count) / float64(time.Millisecond)
		}
		out = append(out, models.TraefikRouterDetail{
			Name:        name,
			Requests:    r.count,
			AvgDuration: avg,
			Service:     r.service,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Requests > out[j].Requests
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

type traefikJSON struct {
	StartUTC           string `json:"StartUTC"`
	StartLocal         string `json:"StartLocal"`
	Time               string `json:"time"`
	T                  string `json:"t"`
	ClientHost         string `json:"ClientHost"`
	ClientAddr         string `json:"ClientAddr"`
	ClientIP           string `json:"client_ip"`
	IP                 string `json:"ip"`
	RemoteAddr         string `json:"RemoteAddr"`
	RequestMethod      string `json:"RequestMethod"`
	Method             string `json:"method"`
	Request_Method     string `json:"request_Method"`
	RequestPath        string `json:"RequestPath"`
	Path               string `json:"path"`
	Request_Path       string `json:"request_Path"`
	DownstreamStatus   int    `json:"DownstreamStatus"`
	Status             int    `json:"status"`
	Downstream_Status  int    `json:"downstream_Status"`
	Duration           int64  `json:"Duration"`
	Duration_Small     int64  `json:"duration"`
	RouterName         string `json:"RouterName"`
	Router             string `json:"router"`
	ServiceName        string `json:"ServiceName"`
	Service            string `json:"service"`
	RequestHost        string `json:"RequestHost"`
	Request_Host       string `json:"request_Host"`
	Host               string `json:"host"`
	OriginHost         string `json:"OriginHost"`
	RequestAddr        string `json:"RequestAddr"`
	Request_Addr       string `json:"request_Addr"`
	TLSVersion         string `json:"TLSVersion"`
	TLS_Version_Small  string `json:"tls_version"`
	UserAgent          string `json:"UserAgent"`
	Request_User_Agent string `json:"request_User-Agent"`
	User_Agent_Small   string `json:"user_agent"`
	UA                 string `json:"ua"`
	ServiceAddr        string `json:"ServiceAddr"`
}

func (r traefikJSON) getUA() string {
	if r.UserAgent != "" { return r.UserAgent }
	if r.Request_User_Agent != "" { return r.Request_User_Agent }
	if r.User_Agent_Small != "" { return r.User_Agent_Small }
	return r.UA
}

func (r traefikJSON) getIP() string {
	if r.ClientHost != "" { return r.ClientHost }
	if r.ClientAddr != "" { return r.ClientAddr }
	if r.ClientIP != "" { return r.ClientIP }
	if r.IP != "" { return r.IP }
	return r.RemoteAddr
}

func (r traefikJSON) getHost() string {
	h := r.RequestHost
	if h == "" { h = r.Request_Host }
	if h == "" { h = r.Host }
	if h == "" { h = r.OriginHost }
	
	if h == "" {
		addr := r.RequestAddr
		if addr == "" { addr = r.Request_Addr }
		if addr != "" {
			if i := strings.LastIndexByte(addr, ':'); i > 0 {
				return addr[:i]
			}
			return addr
		}
	}
	return h
}

func (r traefikJSON) getMethod() string {
	if r.RequestMethod != "" { return r.RequestMethod }
	if r.Method != "" { return r.Method }
	return r.Request_Method
}

func (r traefikJSON) getPath() string {
	if r.RequestPath != "" { return r.RequestPath }
	if r.Path != "" { return r.Path }
	return r.Request_Path
}

func (r traefikJSON) getStatus() int {
	if r.DownstreamStatus != 0 { return r.DownstreamStatus }
	if r.Status != 0 { return r.Status }
	return r.Downstream_Status
}

func (r traefikJSON) getDuration() int64 {
	if r.Duration != 0 { return r.Duration }
	return r.Duration_Small
}

func (r traefikJSON) getRouter() string {
	if r.RouterName != "" { return r.RouterName }
	return r.Router
}

func (r traefikJSON) getService() string {
	if r.ServiceName != "" { return r.ServiceName }
	return r.Service
}

func (r traefikJSON) populated() bool {
	return r.getIP() != "" || r.getStatus() != 0
}

func (r traefikJSON) startTime() time.Time {
	utc := r.StartUTC
	if utc == "" { utc = r.Time }
	if utc == "" { utc = r.T }
	
	if utc != "" {
		if t, err := time.Parse(time.RFC3339Nano, utc); err == nil {
			return t
		}
		if t, err := time.Parse(time.RFC3339, utc); err == nil {
			return t
		}
	}
	local := r.StartLocal
	if local != "" {
		if t, err := time.Parse(time.RFC3339Nano, local); err == nil {
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
		TopPaths:         []models.TraefikPathDetail{},
		TopRouters:       []models.TraefikRouterDetail{},
		TopServices:      []models.TraefikServiceDetail{},
		TopAddresses:     []models.NameValue{},
		UserAgents:       []models.NameValue{},
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
		return time.Hour
	}
}

func calculateDynamicGranularity(span time.Duration) time.Duration {
	if span <= 0 {
		return time.Hour
	}
	// Target ~40 points
	target := span / 40
	if target < time.Minute {
		return time.Minute
	}
	if target < 5*time.Minute {
		return 5 * time.Minute
	}
	if target < 10*time.Minute {
		return 10 * time.Minute
	}
	if target < 15*time.Minute {
		return 15 * time.Minute
	}
	if target < 30*time.Minute {
		return 30 * time.Minute
	}
	if target < time.Hour {
		return time.Hour
	}
	if target < 2*time.Hour {
		return 2 * time.Hour
	}
	if target < 3*time.Hour {
		return 3 * time.Hour
	}
	if target < 4*time.Hour {
		return 4 * time.Hour
	}
	if target < 6*time.Hour {
		return 6 * time.Hour
	}
	if target < 12*time.Hour {
		return 12 * time.Hour
	}
	if target < 24*time.Hour {
		return 24 * time.Hour
	}
	if target < 7*24*time.Hour {
		return 7 * 24 * time.Hour
	}
	return 30 * 24 * time.Hour
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

// isStreamingPath reports whether a Traefik request path is a long-lived
// stream (WebSocket / SSE) where row.Duration measures connection lifetime
// rather than response latency. Mirrors the gzip-exclusion list in
// cmd/server/main.go — keep them in sync.
func isStreamingPath(p string) bool {
	return strings.HasPrefix(p, "/api/logs/stream/") ||
		strings.HasPrefix(p, "/api/events/") ||
		strings.HasPrefix(p, "/api/terminal/")
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

func cleanUserAgent(ua string) string {
	if ua == "" {
		return "Unknown"
	}
	if strings.Contains(ua, "Chrome") && !strings.Contains(ua, "Edg") && !strings.Contains(ua, "OPR") {
		return "Chrome"
	}
	if strings.Contains(ua, "Firefox") {
		return "Firefox"
	}
	if strings.Contains(ua, "Safari") && !strings.Contains(ua, "Chrome") {
		return "Safari"
	}
	if strings.Contains(ua, "Edg") {
		return "Edge"
	}
	if strings.Contains(ua, "OPR") || strings.Contains(ua, "Opera") {
		return "Opera"
	}
	if strings.Contains(ua, "curl") {
		return "Curl"
	}
	if strings.Contains(ua, "Postman") {
		return "Postman"
	}
	if strings.Contains(ua, "Trident") || strings.Contains(ua, "MSIE") {
		return "IE"
	}
	// Fallback to the first word or a truncated version
	parts := strings.Split(ua, " ")
	if len(parts) > 0 {
		if strings.Contains(parts[0], "/") {
			return strings.Split(parts[0], "/")[0]
		}
		return parts[0]
	}
	return "Other"
}
