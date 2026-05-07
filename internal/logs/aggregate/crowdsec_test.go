package aggregate

import (
	"strings"
	"testing"
	"time"

	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
)

func parseCrowdSec(t *testing.T, raw string) []docker.StructuredLogEntry {
	t.Helper()
	parser := docker.NewLogParser()
	return parser.Parse(raw, "crowdsec")
}

func TestBucketCrowdSec_EmptyInput(t *testing.T) {
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	d := BucketCrowdSec(nil, now.Add(-time.Hour), now, models.Range1h, fakeGeo{})
	if d.TotalEvents != 0 || d.Decisions != 0 || d.Alerts != 0 || d.ParserErrors != 0 {
		t.Fatalf("expected zero counters, got %+v", d)
	}
	if d.Series == nil || d.TopScenarios == nil || d.TopSourceIPs == nil ||
		d.TopOrigins == nil || d.TopDecisionTypes == nil || d.Acquisition == nil ||
		d.BouncerActivity == nil || d.RecentErrors == nil {
		t.Fatalf("nil slices must be replaced with empty for JSON: %+v", d)
	}
}

func TestBucketCrowdSec_AggregatesScenariosDecisionsErrors(t *testing.T) {
	logs := strings.Join([]string{
		`time="2026-05-07T11:50:00Z" level=info msg="Ip 1.2.3.4 performed 'http-probing'" scenario="crowdsecurity/http-probing" source_ip=1.2.3.4 type=ban origin=crowdsec`,
		`time="2026-05-07T11:51:00Z" level=info msg="Ip 1.2.3.4 performed 'http-bf'" scenario="crowdsecurity/http-bf" source_ip=1.2.3.4 type=ban origin=crowdsec`,
		`time="2026-05-07T11:52:00Z" level=info msg="alert triggered" scenario="crowdsecurity/http-probing" source_ip=5.6.7.8 type=captcha origin=cscli`,
		`time="2026-05-07T11:53:00Z" level=error msg="parser failed to load file foo"`,
		`time="2026-05-07T11:54:00Z" level=info msg="bouncer foo received decisions" source=bouncer`,
		`time="2026-05-07T11:55:00Z" level=info msg="reading file file:/var/log/auth.log" source=file:/var/log/auth.log`,
	}, "\n")
	entries := parseCrowdSec(t, logs)
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	geo := fakeGeo{hits: map[string]Location{
		"5.6.7.8": {Country: "DE", Lat: 51, Lng: 9},
	}}
	d := BucketCrowdSec(entries, now.Add(-time.Hour), now, models.Range1h, geo)

	if d.TotalEvents != 6 {
		t.Fatalf("expected 6 events, got %d", d.TotalEvents)
	}
	if d.Decisions == 0 {
		t.Fatalf("expected decisions > 0, got %d", d.Decisions)
	}
	if d.ParserErrors != 1 {
		t.Fatalf("expected 1 parser error, got %d", d.ParserErrors)
	}

	// Top scenarios - http-probing (2) ahead of http-bf (1)
	if len(d.TopScenarios) < 2 {
		t.Fatalf("expected at least 2 scenarios; got %+v", d.TopScenarios)
	}
	if d.TopScenarios[0].Name != "crowdsecurity/http-probing" || d.TopScenarios[0].Value != 2 {
		t.Fatalf("unexpected top scenario: %+v", d.TopScenarios[0])
	}

	// Top source IPs sorted desc
	if len(d.TopSourceIPs) == 0 || d.TopSourceIPs[0].IP != "1.2.3.4" || d.TopSourceIPs[0].Count != 2 {
		t.Fatalf("unexpected top source IPs: %+v", d.TopSourceIPs)
	}
	for _, ip := range d.TopSourceIPs {
		if ip.IP == "5.6.7.8" && ip.Country != "DE" {
			t.Fatalf("expected geo lookup for 5.6.7.8, got %+v", ip)
		}
	}

	// Decision types
	gotTypes := map[string]int{}
	for _, kv := range d.TopDecisionTypes {
		gotTypes[kv.Name] = kv.Value
	}
	if gotTypes["ban"] != 2 || gotTypes["captcha"] != 1 {
		t.Fatalf("unexpected decision types: %+v", gotTypes)
	}

	// Origins
	gotOrigins := map[string]int{}
	for _, kv := range d.TopOrigins {
		gotOrigins[kv.Name] = kv.Value
	}
	if gotOrigins["crowdsec"] != 2 || gotOrigins["cscli"] != 1 {
		t.Fatalf("unexpected origins: %+v", gotOrigins)
	}

	// At least one acquisition row should reference the file source
	foundFile := false
	for _, a := range d.Acquisition {
		if strings.Contains(a.Source, "auth.log") || strings.Contains(a.Source, "file:") {
			foundFile = true
			break
		}
	}
	if !foundFile {
		t.Fatalf("expected acquisition to mention file source; got %+v", d.Acquisition)
	}

	// Bouncer activity should include the bouncer line
	hasBouncer := false
	for _, b := range d.BouncerActivity {
		if strings.Contains(strings.ToLower(b.Message), "bouncer") {
			hasBouncer = true
			break
		}
	}
	if !hasBouncer {
		t.Fatalf("expected at least one bouncer activity row; got %+v", d.BouncerActivity)
	}

	// Recent errors should include the parser error
	if len(d.RecentErrors) == 0 || d.RecentErrors[0].Level != "error" {
		t.Fatalf("expected at least one error row; got %+v", d.RecentErrors)
	}
}

func TestBucketCrowdSec_ExtractsScenarioFromMessageText(t *testing.T) {
	// Real-world CrowdSec lines from a docker container — scenario, ip, type
	// and origin are inside the msg= text rather than as key=value pairs.
	logs := strings.Join([]string{
		`time="2026-05-07T10:20:19Z" level=info msg="Ip 20.9.31.235 performed 'crowdsecurity/http-probing' (11 events over 386.892261ms) at 2026-05-07 10:20:19 +0000 UTC"`,
		`time="2026-05-07T10:20:19Z" level=info msg="(localhost/crowdsec) crowdsecurity/http-probing by ip 20.9.31.235 (US/8075) : 4h captcha on Ip 20.9.31.235" module=db`,
		`time="2026-05-07T10:20:21Z" level=info msg="(localhost/crowdsec) crowdsecurity/http-crawl-non_statics by ip 20.9.31.235 (US/8075) : 4h captcha on Ip 20.9.31.235" module=db`,
		`time="2026-05-07T10:20:23Z" level=info msg="(localhost/crowdsec) crowdsecurity/http-backdoors-attempts by ip 20.9.31.235 (US/8075) : 4h ban on Ip 20.9.31.235" module=db`,
	}, "\n")
	entries := parseCrowdSec(t, logs)
	now := time.Date(2026, 5, 7, 11, 0, 0, 0, time.UTC)
	d := BucketCrowdSec(entries, now.Add(-time.Hour), now, models.Range1h, fakeGeo{})

	if d.Alerts == 0 {
		t.Fatalf("expected alert detected from 'Ip ... performed' message; got %+v", d)
	}
	if d.Decisions < 3 {
		t.Fatalf("expected at least 3 decisions from db msgs; got %d", d.Decisions)
	}

	scenarios := map[string]int{}
	for _, kv := range d.TopScenarios {
		scenarios[kv.Name] = kv.Value
	}
	if scenarios["crowdsecurity/http-probing"] == 0 {
		t.Fatalf("expected http-probing scenario, got %+v", scenarios)
	}

	types := map[string]int{}
	for _, kv := range d.TopDecisionTypes {
		types[kv.Name] = kv.Value
	}
	if types["captcha"] == 0 || types["ban"] == 0 {
		t.Fatalf("expected captcha and ban decisions; got %+v", types)
	}

	if len(d.TopSourceIPs) == 0 || d.TopSourceIPs[0].IP != "20.9.31.235" {
		t.Fatalf("expected 20.9.31.235 as top source IP; got %+v", d.TopSourceIPs)
	}

	origins := map[string]int{}
	for _, kv := range d.TopOrigins {
		origins[kv.Name] = kv.Value
	}
	if origins["crowdsec"] == 0 {
		t.Fatalf("expected crowdsec origin from '(localhost/crowdsec)'; got %+v", origins)
	}
}

func TestBucketCrowdSec_LapiNoiseDoesNotProduceFalseDecisions(t *testing.T) {
	// LAPI access lines should not be miscounted as decisions/alerts.
	logs := strings.Join([]string{
		`time="2026-05-07T10:13:09Z" level=info msg="127.0.0.1 - [Thu, 07 May 2026 10:13:09 UTC] \"POST /v1/watchers/login HTTP/1.1 200 63ms \"crowdsec/v1.7.7\" \"" module=lapi`,
		`time="2026-05-07T10:13:11Z" level=info msg="172.20.0.48 - [Thu, 07 May 2026 10:13:11 UTC] \"GET /v1/decisions?ip=1.2.3.4 HTTP/1.1 200 26ms \"Crowdsec-Bouncer-Traefik-Plugin/1.X.X\" \"" module=lapi`,
	}, "\n")
	entries := parseCrowdSec(t, logs)
	now := time.Date(2026, 5, 7, 11, 0, 0, 0, time.UTC)
	d := BucketCrowdSec(entries, now.Add(-time.Hour), now, models.Range1h, fakeGeo{})

	if d.Alerts != 0 || d.Decisions != 0 {
		t.Fatalf("LAPI lines should not be counted as alerts/decisions; got alerts=%d decisions=%d", d.Alerts, d.Decisions)
	}
	if d.TotalEvents != 2 {
		t.Fatalf("expected 2 events, got %d", d.TotalEvents)
	}
}

func TestBucketCrowdSec_FiltersByCutoff(t *testing.T) {
	logs := strings.Join([]string{
		`time="2026-05-07T09:00:00Z" level=info msg="old" scenario="x" source_ip=1.1.1.1 type=ban`, // before cutoff
		`time="2026-05-07T11:55:00Z" level=info msg="new" scenario="x" source_ip=1.1.1.1 type=ban`,
	}, "\n")
	entries := parseCrowdSec(t, logs)
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	d := BucketCrowdSec(entries, now.Add(-time.Hour), now, models.Range1h, fakeGeo{})
	if d.TotalEvents != 1 {
		t.Fatalf("expected 1 event after cutoff filter, got %d", d.TotalEvents)
	}
}
