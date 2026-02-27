# Debug Findings

## Issue 1: Hub Browser Blank Page

**Root Cause:** `cscli hub list -o json` outputs informational preamble lines to stdout before the JSON:

```
Loaded: 161 parsers, 11 postoverflows, 774 scenarios, 9 contexts, 5 appsec-configs, 187 appsec-rules, 160 collections
Unmanaged items: 1 local, 0 tainted
{
  "appsec-configs": [...],
  "collections": [...],
  ...
}
```

The backend `ListHubItems` handler tried to `json.Unmarshal` the full output (including preamble), which failed. It then returned the raw string as `Data`. The frontend `parseHubItems` attempted `JSON.parse` on it, which also failed due to the preamble text, resulting in `rawParseError: true` and empty items — a blank page.

Additionally, the frontend `HUB_TABS` only listed 4 categories (`scenarios`, `parsers`, `collections`, `postoverflows`) but CrowdSec now returns 7 categories (adding `appsec-configs`, `appsec-rules`, `contexts`).

**Fix (Backend):** `internal/api/handlers/hub.go` — Strip any text before the first `{` character in `ListHubItems` and `ListHubItemsByCategory` before attempting JSON parse.

**Fix (Frontend):**
- `web/src/pages/HubBrowser.tsx` — Added `appsec-configs`, `appsec-rules`, `contexts` to `HubItemType`, `HUB_TABS`, `EMPTY_HUB_ITEMS`, and `parseHubItems`.
- `web/src/lib/api/hub.ts` — Added `contexts` to `HubCategoryKey` type.
- `web/src/pages/HubCategory.tsx` — Added `contexts` to `categoryMeta`.

## Issue 2: Manual Decisions Not Showing in Decisions UI

**Root Cause:** Manual decisions added via `cscli decisions add` produce a different JSON structure. Regular decisions are nested inside alerts (`alert.decisions[]`), but manual decisions appear as flat top-level objects without a `decisions` sub-array. The `GetDecisions` handler only parsed nested decisions, missing the flat ones.

**Fix:** Added fallback parsing in `GetDecisions` and `GetDecisionsAnalysis` — if no nested `decisions` array is found within an alert, check if the top-level item itself has decision fields (e.g. `type`). If so, parse it as a standalone decision. The shared `parseDecisionNode` helper in `common.go` is used for both paths.

## Issue 3: Notification Profiles YAML Formatting

**Root Cause:** `updateProfilesYaml` in `notifications_yaml.go` used `yaml.FlowStyle` for the notifications sequence node, producing `notifications: [discord]` instead of block style. Also used `encoder.SetIndent(2)` instead of matching CrowdSec's default 1-space indent.

**Fix:** Removed `FlowStyle` from sequence nodes and changed `encoder.SetIndent(1)` to match CrowdSec profiles.yaml format.
