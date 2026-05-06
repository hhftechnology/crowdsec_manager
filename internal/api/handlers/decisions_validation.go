package handlers

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors for AddDecisionRequest validation. Callers use errors.Is
// to map these to specific HTTP responses.
var (
	ErrNoSelector         = errors.New("at least one selector mode is required: ip, range, or scope and value")
	ErrIPAndRange         = errors.New("ip and range are mutually exclusive")
	ErrMixedSelector      = errors.New("ip, range, and scope/value selector modes are mutually exclusive")
	ErrIncompleteSelector = errors.New("scope and value must be provided together")
)

// permanentDurations are user-supplied values we treat as "no expiry" — we
// silently drop the cscli --duration flag so cscli applies its default
// (permanent for cscli decisions add).
var permanentDurations = map[string]struct{}{
	"":          {},
	"0":         {},
	"0s":        {},
	"permanent": {},
	"never":     {},
	"forever":   {},
}

// daysWeeksPattern matches "1d", "30d", "1w", "2w" (positive integer + d|w).
// Go's time.ParseDuration does not accept these units, so we translate them
// to hours before passing to cscli (which uses Go's parser internally).
var daysWeeksPattern = regexp.MustCompile(`^(\d+)([dw])$`)

// NormalizeDuration takes a user-supplied duration string and returns:
//   - ("", true) when the --duration flag should be omitted (permanent)
//   - (canonicalDuration, true) when the duration is valid and should be passed
//   - ("", false) when the input is invalid
//
// Days and weeks are translated to hours because cscli (built on Go's
// time.ParseDuration) does not natively support those units.
func NormalizeDuration(input string) (string, bool) {
	trimmed := strings.TrimSpace(strings.ToLower(input))
	if _, ok := permanentDurations[trimmed]; ok {
		return "", true
	}

	if m := daysWeeksPattern.FindStringSubmatch(trimmed); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil || n <= 0 {
			return "", false
		}
		hoursPerUnit := 24
		if m[2] == "w" {
			hoursPerUnit = 24 * 7
		}
		return fmt.Sprintf("%dh", n*hoursPerUnit), true
	}

	d, err := time.ParseDuration(trimmed)
	if err != nil || d <= 0 {
		return "", false
	}
	return trimmed, true
}

// ValidateAddDecisionRequest enforces cscli's flag rules before we exec.
// Returns one of the sentinel errors so the handler can pick the right
// HTTP status / message; nil means the request is acceptable.
func ValidateAddDecisionRequest(req *AddDecisionRequest) error {
	if req == nil {
		return ErrNoSelector
	}

	hasIP := strings.TrimSpace(req.IP) != ""
	hasRange := strings.TrimSpace(req.Range) != ""
	hasScope := strings.TrimSpace(req.Scope) != ""
	hasValue := strings.TrimSpace(req.Value) != ""
	hasScopeValue := hasScope || hasValue

	if !hasIP && !hasRange && !hasScopeValue {
		return ErrNoSelector
	}
	if hasIP && hasRange {
		return ErrIPAndRange
	}
	if hasScopeValue && (!hasScope || !hasValue) {
		return ErrIncompleteSelector
	}
	if (hasIP || hasRange) && hasScopeValue {
		return ErrMixedSelector
	}

	return nil
}
