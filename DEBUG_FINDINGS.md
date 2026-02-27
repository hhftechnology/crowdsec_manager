# Debug Findings: Decisions UI & Hub Browser

## Issue 1: Manual Decisions Not Showing in Decisions UI

### Symptoms
- Adding a decision via `cscli decisions add` (or the UI's "Add Decision" form) does not appear in the Decisions page
- The same decision DOES appear in the Alerts page

### Root Cause

**The JSON parser in `GetDecisions` and `GetDecisionsAnalysis` assumes decisions are always nested inside alerts.**

The `cscli decisions list -o json` output wraps decisions inside an alerts array:
```json
[
  {
    "id": 1,
    "created_at": "...",
    "decisions": [
      { "id": 1, "type": "ban", "value": "1.2.3.4", ... }
    ]
  }
]
```

The parser uses nested `jsonparser.ArrayEach`:
- Outer loop: iterates over top-level array (alerts)
- Inner loop: iterates over `decisions` field within each alert

When `cscli decisions add` creates a manual decision, the top-level JSON entry may have the decision fields directly on the alert object (or the `decisions` sub-array may be structured differently). The nested parser silently skips entries that don't match the expected structure.

### Files Affected
- `internal/api/handlers/dashboard.go:72-128` - `GetDecisions` parser
- `internal/api/handlers/dashboard_analysis.go:78-134` - `GetDecisionsAnalysis` parser

### Fix
Add a fallback: after the nested parsing, check if each top-level item has decision-like fields (type, value, scope) directly on it. If so, extract it as a decision directly.

---

## Issue 2: Hub Browser Shows Blank Page

### Symptoms
- Hub Browser page loads but displays empty/no items
- No error shown, just blank content

### Root Cause

**The `?? null` coercion in the query function converts valid data to null.**

In `web/src/pages/HubBrowser.tsx:106`:
```typescript
return response.data.data ?? null
```

The `parseHubItems` function (line 56) treats `null` as "no data":
```typescript
if (!data) return { items: EMPTY_HUB_ITEMS, rawParseError: false }
```

The actual issue is likely that `response.data.data` returns `undefined` or the response envelope is structured differently than expected. The `?? null` was added defensively but masks the real problem.

The backend `ListHubItems` (hub.go:234) returns:
```go
c.JSON(http.StatusOK, models.Response{
    Success: true,
    Data:    parsed,  // parsed JSON from cscli hub list
})
```

The frontend accesses `response.data.data` where:
- `response.data` = the axios response body (the `models.Response` envelope)
- `response.data.data` = the `Data` field of the envelope

If the `cscli hub list -o json` output structure changed, `parsed` could be a different shape than expected.

### Files Affected
- `web/src/pages/HubBrowser.tsx:106` - query function with `?? null`
- `web/src/pages/HubBrowser.tsx:55-81` - `parseHubItems` parser

### Fix
Remove the `?? null` coercion. The `parseHubItems` function already handles undefined/null/string/object/array cases defensively. The `?? null` just forces the "no data" path unnecessarily.
