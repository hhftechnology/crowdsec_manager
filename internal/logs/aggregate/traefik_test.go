package aggregate

import (
	"strings"
	"testing"
	"time"

	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
)

type fakeGeo struct {
	hits map[string]Location
}

func (f fakeGeo) Lookup(ip string) (Location, bool) {
	loc, ok := f.hits[ip]
	return loc, ok
}

func testSystemStats() *models.SystemStats {
	return &models.SystemStats{}
}

func parseEntries(t *testing.T, raw string) []docker.StructuredLogEntry {
	t.Helper()
	parser := docker.NewLogParser()
	return parser.Parse(raw, "traefik")
}

func TestBucketTraefik_EmptyInput(t *testing.T) {
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	d := BucketTraefik(nil, now.Add(-time.Hour), now, models.Range1h, fakeGeo{}, testSystemStats())
	if d.Format != "clf" {
		t.Fatalf("default format should be clf when nothing parses as JSON; got %q", d.Format)
	}
	if d.TotalRequests != 0 || d.UniqueIPs != 0 || d.ErrorRate != 0 {
		t.Fatalf("expected zero counters; got %+v", d)
	}
	if d.Series == nil || d.StatusCodes == nil || d.Methods == nil ||
		d.TopIPs == nil || d.TopHosts == nil || d.TopRouters == nil ||
		d.SlowestEndpoints == nil || d.TLSVersions == nil || d.RecentErrors == nil {
		t.Fatalf("nil slices must be replaced with empty slices for JSON serialisation: %+v", d)
	}
}

func TestBucketTraefik_CLFAggregates(t *testing.T) {
	logs := strings.Join([]string{
		// CLF: ip - - [time] "METHOD path HTTP" status size
		`1.2.3.4 - - [07/May/2026:11:55:00 +0000] "GET /a HTTP/1.1" 200 100`,
		`1.2.3.4 - - [07/May/2026:11:56:00 +0000] "GET /a HTTP/1.1" 200 100`,
		`5.6.7.8 - - [07/May/2026:11:57:00 +0000] "POST /b HTTP/1.1" 500 200`,
		`9.9.9.9 - - [07/May/2026:11:58:00 +0000] "GET /c HTTP/1.1" 404 50`,
	}, "\n")
	entries := parseEntries(t, logs)
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	geo := fakeGeo{hits: map[string]Location{
		"5.6.7.8": {Country: "DE", Lat: 51, Lng: 9},
	}}
	d := BucketTraefik(entries, now.Add(-time.Hour), now, models.Range1h, geo, testSystemStats())

	if d.Format != "clf" {
		t.Fatalf("expected CLF format, got %q", d.Format)
	}
	if d.TotalRequests != 4 {
		t.Fatalf("expected 4 requests, got %d", d.TotalRequests)
	}
	if d.UniqueIPs != 3 {
		t.Fatalf("expected 3 unique IPs, got %d", d.UniqueIPs)
	}
	// 1 5xx + 1 4xx out of 4 = 0.5
	if d.ErrorRate != 0.5 {
		t.Fatalf("expected error rate 0.5, got %v", d.ErrorRate)
	}
	if d.AvgDurationMs != nil {
		t.Fatalf("CLF mode must not produce avg duration; got %v", *d.AvgDurationMs)
	}

	// Status codes summed
	codeCounts := map[string]int{}
	for _, kv := range d.StatusCodes {
		codeCounts[kv.Name] = kv.Value
	}
	if codeCounts["200"] != 2 || codeCounts["404"] != 1 || codeCounts["500"] != 1 {
		t.Fatalf("unexpected status counts: %+v", codeCounts)
	}

	// Methods
	methodCounts := map[string]int{}
	for _, kv := range d.Methods {
		methodCounts[kv.Name] = kv.Value
	}
	if methodCounts["GET"] != 3 || methodCounts["POST"] != 1 {
		t.Fatalf("unexpected method counts: %+v", methodCounts)
	}

	// Top IPs sorted by count desc; 1.2.3.4 first
	if len(d.TopIPs) == 0 || d.TopIPs[0].IP != "1.2.3.4" || d.TopIPs[0].Count != 2 {
		t.Fatalf("top IP wrong: %+v", d.TopIPs)
	}
	// GeoIP populated for 5.6.7.8
	for _, ip := range d.TopIPs {
		if ip.IP == "5.6.7.8" && ip.Country != "DE" {
			t.Fatalf("expected DE for 5.6.7.8, got %+v", ip)
		}
	}

	// Recent errors should include 4xx and 5xx, sorted recent-first
	if len(d.RecentErrors) != 2 {
		t.Fatalf("expected 2 recent errors, got %d", len(d.RecentErrors))
	}
	if d.RecentErrors[0].Status < 400 {
		t.Fatalf("recent errors must only contain 4xx/5xx; got %+v", d.RecentErrors)
	}
}

func TestBucketTraefik_FiltersByCutoff(t *testing.T) {
	logs := strings.Join([]string{
		`1.2.3.4 - - [07/May/2026:09:00:00 +0000] "GET /old HTTP/1.1" 200 100`, // before cutoff
		`1.2.3.4 - - [07/May/2026:11:55:00 +0000] "GET /new HTTP/1.1" 200 100`, // inside
	}, "\n")
	entries := parseEntries(t, logs)
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	d := BucketTraefik(entries, now.Add(-time.Hour), now, models.Range1h, fakeGeo{}, testSystemStats())
	if d.TotalRequests != 1 {
		t.Fatalf("expected 1 request after cutoff filtering, got %d", d.TotalRequests)
	}
}

func TestBucketTraefik_JSONFormatPopulatesExtras(t *testing.T) {
	// Traefik JSON access log lines (one JSON object per line).
	logs := strings.Join([]string{
		`{"ClientHost":"1.2.3.4","DownstreamStatus":200,"RequestMethod":"GET","RequestHost":"example.com","RouterName":"router-a@docker","RequestPath":"/x","Duration":12000000,"StartUTC":"2026-05-07T11:50:00Z","TLSVersion":"1.3"}`,
		`{"ClientHost":"5.6.7.8","DownstreamStatus":500,"RequestMethod":"POST","RequestHost":"api.example.com","RouterName":"router-b@docker","RequestPath":"/y","Duration":40000000,"StartUTC":"2026-05-07T11:55:00Z","TLSVersion":"1.2"}`,
	}, "\n")
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	d := BucketTraefikRaw(logs, now.Add(-time.Hour), now, models.Range1h, fakeGeo{}, testSystemStats())

	if d.Format != "json" {
		t.Fatalf("expected json format when JSON lines present, got %q", d.Format)
	}
	if d.AvgDurationMs == nil {
		t.Fatalf("expected non-nil avg duration in JSON mode")
	}
	// Duration in nanoseconds: 12ms and 40ms -> avg 26ms
	if got := *d.AvgDurationMs; got < 25 || got > 27 {
		t.Fatalf("expected avg duration ~26ms, got %v", got)
	}
	if d.P95ResponseTimeMs == nil || *d.P95ResponseTimeMs < 38 || *d.P95ResponseTimeMs > 39 {
		t.Fatalf("expected interpolated p95 around 38.6ms, got %v", d.P95ResponseTimeMs)
	}
	if d.P99ResponseTimeMs == nil || *d.P99ResponseTimeMs < 39 || *d.P99ResponseTimeMs > 40 {
		t.Fatalf("expected interpolated p99 around 39.7ms, got %v", d.P99ResponseTimeMs)
	}
	if len(d.TopHosts) == 0 || len(d.TopRouters) == 0 {
		t.Fatalf("JSON mode should populate hosts/routers; got %+v / %+v", d.TopHosts, d.TopRouters)
	}
	if len(d.TLSVersions) == 0 {
		t.Fatalf("JSON mode should populate TLS versions")
	}
	if len(d.SlowestEndpoints) == 0 {
		t.Fatalf("JSON mode should populate slowest endpoints")
	}
}

func TestBucketTraefik_SlowestEndpointsExcludesStreaming(t *testing.T) {
	// A long-lived WebSocket stream (5 min) and a regular REST call (800 ms).
	// The stream's duration is connection lifetime, not latency, and must not
	// appear in SlowestEndpoints.
	logs := strings.Join([]string{
		`{"ClientHost":"1.2.3.4","DownstreamStatus":101,"RequestMethod":"GET","RequestHost":"example.com","RequestPath":"/api/logs/stream/traefik","Duration":300000000000,"StartUTC":"2026-05-07T11:50:00Z"}`,
		`{"ClientHost":"5.6.7.8","DownstreamStatus":200,"RequestMethod":"GET","RequestHost":"example.com","RequestPath":"/api/health","Duration":800000000,"StartUTC":"2026-05-07T11:55:00Z"}`,
		`{"ClientHost":"9.9.9.9","DownstreamStatus":200,"RequestMethod":"GET","RequestHost":"example.com","RequestPath":"/api/events/sse","Duration":120000000000,"StartUTC":"2026-05-07T11:56:00Z"}`,
		`{"ClientHost":"9.9.9.9","DownstreamStatus":101,"RequestMethod":"GET","RequestHost":"example.com","RequestPath":"/api/terminal/abc","Duration":60000000000,"StartUTC":"2026-05-07T11:57:00Z"}`,
	}, "\n")
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	d := BucketTraefikRaw(logs, now.Add(-time.Hour), now, models.Range1h, fakeGeo{}, testSystemStats())

	if d.Format != "json" {
		t.Fatalf("expected json format, got %q", d.Format)
	}
	if d.TotalRequests != 4 {
		t.Fatalf("streaming requests must still count toward totals; got %d", d.TotalRequests)
	}
	if len(d.SlowestEndpoints) != 1 {
		t.Fatalf("expected exactly one non-streaming endpoint; got %+v", d.SlowestEndpoints)
	}
	if d.SlowestEndpoints[0].Name != "/api/health" {
		t.Fatalf("expected /api/health as the only slowest endpoint; got %+v", d.SlowestEndpoints)
	}
	for _, kv := range d.SlowestEndpoints {
		if isStreamingPath(kv.Name) {
			t.Fatalf("streaming path %q must not appear in SlowestEndpoints", kv.Name)
		}
	}
}

func TestBucketTraefik_GranularityChoice(t *testing.T) {
	// 24h range should bucket by hour, not minute.
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	d := BucketTraefik(nil, now.Add(-24*time.Hour), now, models.Range24h, fakeGeo{}, testSystemStats())
	if d.Range != models.Range24h {
		t.Fatalf("range echoed wrong: %s", d.Range)
	}
}
