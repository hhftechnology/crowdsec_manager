package docker

import (
	"regexp"
	"strings"
	"time"
)

// StructuredLogEntry represents a parsed log line with structured fields
type StructuredLogEntry struct {
	Timestamp time.Time         `json:"timestamp"`
	Level     string            `json:"level"`
	Source    string            `json:"source"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
	Raw       string            `json:"raw"`
}

// LogParser parses container logs into structured entries
type LogParser struct {
	patterns []logPattern
}

type logPattern struct {
	name  string
	regex *regexp.Regexp
}

// NewLogParser creates a parser with patterns for CrowdSec and generic logs.
func NewLogParser() *LogParser {
	return &LogParser{
		patterns: []logPattern{
			{
				name: "crowdsec",
				// CrowdSec log format: time="2024-01-15T10:30:00Z" level=info msg="something" key=value
				regex: regexp.MustCompile(`^time="([^"]+)"\s+level=(\w+)\s+msg="([^"]*)"(.*)$`),
			},
			{
				name: "crowdsec_json",
				// CrowdSec JSON-like: {"level":"info","msg":"something","time":"..."}
				regex: regexp.MustCompile(`^\{".*"level":"(\w+)".*"msg":"([^"]*)".*"time":"([^"]*)".*\}$`),
			},
			{
				name: "generic_timestamp",
				// Generic: 2024-01-15T10:30:00Z level message
				regex: regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)\s+(\w+)\s+(.*)$`),
			},
		},
	}
}

// Parse parses a raw log string into structured entries
func (p *LogParser) Parse(rawLogs string, source string) []StructuredLogEntry {
	lines := strings.Split(rawLogs, "\n")
	entries := make([]StructuredLogEntry, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		entry := p.parseLine(line, source)
		entries = append(entries, entry)
	}

	return entries
}

func (p *LogParser) parseLine(line, source string) StructuredLogEntry {
	entry := StructuredLogEntry{
		Source: source,
		Raw:    line,
		Fields: make(map[string]string),
	}

	for _, pat := range p.patterns {
		matches := pat.regex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		switch pat.name {
		case "crowdsec":
			entry.Timestamp = parseTimestamp(matches[1])
			entry.Level = matches[2]
			entry.Message = matches[3]
			// Parse remaining key=value pairs
			if len(matches) > 4 {
				parseKeyValues(matches[4], entry.Fields)
			}
			return entry

		case "crowdsec_json":
			entry.Level = matches[1]
			entry.Message = matches[2]
			entry.Timestamp = parseTimestamp(matches[3])
			return entry

		case "generic_timestamp":
			entry.Timestamp = parseTimestamp(matches[1])
			entry.Level = strings.ToLower(matches[2])
			entry.Message = matches[3]
			return entry
		}
	}

	// Fallback: unparsed line
	entry.Message = line
	entry.Level = "info"
	entry.Timestamp = time.Now()
	return entry
}

// GetStructuredLogs retrieves and parses container logs
func (c *Client) GetStructuredLogs(containerName, tail, source string) ([]StructuredLogEntry, error) {
	rawLogs, err := c.GetContainerLogs(containerName, tail)
	if err != nil {
		return nil, err
	}

	parser := NewLogParser()
	return parser.Parse(rawLogs, source), nil
}

// parseTimestamp attempts to parse various timestamp formats
func parseTimestamp(s string) time.Time {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.000Z",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	return time.Now()
}

// parseKeyValues parses "key=value key2=value2" into a map
func parseKeyValues(s string, fields map[string]string) {
	kvRegex := regexp.MustCompile(`(\w+)=(?:"([^"]*)"|(\S+))`)
	matches := kvRegex.FindAllStringSubmatch(s, -1)
	for _, m := range matches {
		key := m[1]
		value := m[2]
		if value == "" {
			value = m[3]
		}
		fields[key] = value
	}
}
