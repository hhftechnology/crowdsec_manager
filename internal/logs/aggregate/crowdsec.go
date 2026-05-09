package aggregate

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
)

// CrowdSec produces structured-looking log lines but the interesting
// fields (scenario, source IP, decision type, origin) sit inside the
// human-readable msg= rather than as key=value pairs. These regexes
// recover them so the dashboard isn't all zeros against a real engine.

// alertRe matches "Ip 1.2.3.4 performed 'scenario_name' (...)".
var alertRe = regexp.MustCompile(`(?i)\bIp\s+(\S+)\s+performed\s+'([^']+)'`)

// decisionRe matches "(localhost/crowdsec) scenario_name by ip 1.2.3.4 (US/8075) : 4h captcha on Ip 1.2.3.4".
// Captures: origin, scenario, ip, country/asn payload, decision type.
var decisionRe = regexp.MustCompile(`(?i)\(([^/]+)/([^)]+)\)\s+(\S+)\s+by\s+ip\s+(\S+)\s+\(([^)]+)\)\s*:\s*\S+\s+(\w+)\s+on`)

const (
	maxTopScenarios     = 10
	maxTopOrigins       = 10
	maxTopDecisionTypes = 10
	maxAcquisition      = 10
	maxBouncerActivity  = 50
	maxCrowdSecErrors   = 50
)

// BucketCrowdSec aggregates parsed CrowdSec entries (key=value format)
// into the dashboard payload.
func BucketCrowdSec(entries []docker.StructuredLogEntry, since, now time.Time, rng models.DashboardRange, geo GeoLookup) models.CrowdSecDashboard {
	if geo == nil {
		geo = noGeo{}
	}
	out := emptyCrowdSecDashboard(rng, now)

	gran := bucketGranularity(rng)
	buckets := map[time.Time]*models.CrowdSecBucket{}
	scenarioCounts := map[string]int{}
	sourceIPCounts := map[string]int{}
	originCounts := map[string]int{}
	typeCounts := map[string]int{}
	acquisitionCounts := map[string]int{}

	var bouncerRows []models.CrowdSecActivity
	var errorRows []models.CrowdSecActivity
	var totalEvents, decisions, alerts, parserErrors int

	for _, e := range entries {
		ts := e.Timestamp
		if ts.IsZero() {
			continue
		}
		if !since.IsZero() && ts.Before(since) {
			continue
		}

		totalEvents++
		level := strings.ToLower(e.Level)

		bucketKey := ts.Truncate(gran).UTC()
		b, ok := buckets[bucketKey]
		if !ok {
			b = &models.CrowdSecBucket{T: bucketKey.Format(time.RFC3339)}
			buckets[bucketKey] = b
		}

		scenario := e.Fields["scenario"]
		decisionType := e.Fields["type"]
		origin := e.Fields["origin"]
		sourceIP := firstNonEmpty(e.Fields["source_ip"], e.Fields["ip"])

		// Most CrowdSec engine lines carry these as msg= text, not
		// key=value. Recover them with regex so the dashboard reflects
		// real activity. msg-extracted decisions also imply a scenario.
		if m := alertRe.FindStringSubmatch(e.Message); m != nil {
			if sourceIP == "" {
				sourceIP = m[1]
			}
			if scenario == "" {
				scenario = m[2]
			}
		}
		if m := decisionRe.FindStringSubmatch(e.Message); m != nil {
			if origin == "" {
				origin = m[2] // "crowdsec" from "(localhost/crowdsec)"
			}
			if scenario == "" {
				scenario = m[3]
			}
			if sourceIP == "" {
				sourceIP = m[4]
			}
			if decisionType == "" {
				decisionType = strings.ToLower(m[6])
			}
		}

		if scenario != "" {
			scenarioCounts[scenario]++
			alerts++
			b.Alerts++
		}
		if decisionType != "" {
			typeCounts[decisionType]++
			decisions++
			b.Decisions++
		}
		if origin != "" {
			originCounts[origin]++
		}
		if sourceIP != "" {
			sourceIPCounts[sourceIP]++
		}

		// acquisition source: prefer explicit source/file fields; fall back
		// to the message when CrowdSec logs "reading file ..."
		if src := acquisitionSource(e); src != "" {
			acquisitionCounts[src]++
		}

		messageLower := strings.ToLower(e.Message)
		if level == "error" || level == "fatal" {
			b.Errors++
			row := models.CrowdSecActivity{
				T:       ts.UTC().Format(time.RFC3339),
				Level:   level,
				Source:  e.Fields["source"],
				Message: e.Message,
			}
			errorRows = append(errorRows, row)
			if strings.Contains(messageLower, "parser") || strings.Contains(messageLower, "parse") {
				parserErrors++
			}
		}

		if strings.Contains(messageLower, "bouncer") || strings.EqualFold(e.Fields["source"], "bouncer") {
			bouncerRows = append(bouncerRows, models.CrowdSecActivity{
				T:       ts.UTC().Format(time.RFC3339),
				Level:   level,
				Source:  e.Fields["source"],
				Message: e.Message,
			})
		}
	}

	out.TotalEvents = totalEvents
	out.Decisions = decisions
	out.Alerts = alerts
	out.ParserErrors = parserErrors

	out.Series = sortedCrowdSecBuckets(buckets)
	out.TopScenarios = topNameValues(scenarioCounts, maxTopScenarios)
	out.TopOrigins = topNameValues(originCounts, maxTopOrigins)
	out.TopDecisionTypes = topNameValues(typeCounts, maxTopDecisionTypes)
	out.TopSourceIPs = topIPs(sourceIPCounts, geo, maxTopIPs)

	out.Acquisition = topAcquisition(acquisitionCounts, maxAcquisition)
	out.BouncerActivity = sortedActivity(bouncerRows, maxBouncerActivity)
	out.RecentErrors = sortedActivity(errorRows, maxCrowdSecErrors)

	return out
}

func emptyCrowdSecDashboard(rng models.DashboardRange, now time.Time) models.CrowdSecDashboard {
	return models.CrowdSecDashboard{
		Range:            rng,
		GeneratedAt:      now.UTC().Format(time.RFC3339),
		Series:           []models.CrowdSecBucket{},
		TopScenarios:     []models.NameValue{},
		TopSourceIPs:     []models.IPStat{},
		TopOrigins:       []models.NameValue{},
		TopDecisionTypes: []models.NameValue{},
		Acquisition:      []models.AcquisitionStat{},
		BouncerActivity:  []models.CrowdSecActivity{},
		RecentErrors:     []models.CrowdSecActivity{},
	}
}

func sortedCrowdSecBuckets(buckets map[time.Time]*models.CrowdSecBucket) []models.CrowdSecBucket {
	keys := make([]time.Time, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Before(keys[j]) })
	out := make([]models.CrowdSecBucket, 0, len(keys))
	for _, k := range keys {
		out = append(out, *buckets[k])
	}
	return out
}

func topAcquisition(counts map[string]int, limit int) []models.AcquisitionStat {
	out := make([]models.AcquisitionStat, 0, len(counts))
	for src, n := range counts {
		out = append(out, models.AcquisitionStat{Source: src, Lines: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Lines != out[j].Lines {
			return out[i].Lines > out[j].Lines
		}
		return out[i].Source < out[j].Source
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func sortedActivity(rows []models.CrowdSecActivity, limit int) []models.CrowdSecActivity {
	if rows == nil {
		return []models.CrowdSecActivity{}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].T > rows[j].T })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

func acquisitionSource(e docker.StructuredLogEntry) string {
	for _, key := range []string{"file", "source"} {
		if v := e.Fields[key]; v != "" && !strings.EqualFold(v, "bouncer") {
			return v
		}
	}
	if strings.Contains(strings.ToLower(e.Message), "reading file") {
		// crude extraction: take the trailing token starting with file:/ or /
		fields := strings.Fields(e.Message)
		for i := len(fields) - 1; i >= 0; i-- {
			f := fields[i]
			if strings.HasPrefix(f, "file:") || strings.HasPrefix(f, "/") {
				return f
			}
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
