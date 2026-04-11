// TypeScript Interfaces matching backend models

export interface ApiResponse<T = unknown> {
  success: boolean
  message?: string
  data?: T
  error?: string
}

export interface Container {
  name: string
  id: string
  status: string
  running: boolean
}

export interface HealthStatus {
  containers: Container[]
  allRunning: boolean
  timestamp: string
}

export interface Decision {
  id: number
  alert_id: number
  origin: string
  type: string
  scope: string
  value: string
  duration: string
  scenario: string
  created_at: string
  until?: string
}

export interface AddDecisionRequest {
  ip?: string
  range?: string
  duration?: string
  type?: string
  scope?: string
  value?: string
  reason?: string
}

export interface DeleteDecisionRequest {
  id?: string
  ip?: string
  range?: string
  type?: string
  scope?: string
  value?: string
  scenario?: string
  origin?: string
}

export interface Bouncer {
  name: string
  ip_address: string
  valid: boolean
  last_pull: string
  type: string
  version: string
  status?: string
}

export interface LogEntry {
  timestamp: string
  level: string
  service: string
  message: string
}

export interface Scenario {
  name: string
  description: string
  content: string
}

export interface ScenarioSetupRequest {
  scenarios: Scenario[]
}

export interface Metric {
  name: string
  value: number
  labels?: Record<string, string>
}

export interface DiagnosticResult {
  health: HealthStatus
  bouncers: Bouncer[]
  decisions: Decision[]
  timestamp: string
}

export interface ServiceActionRequest {
  service: string
  action: 'start' | 'stop' | 'restart'
}

export interface EnrollRequest {
  enrollment_key: string
  name?: string
  disable_context?: boolean
}

export interface ConsoleStatus {
  enrolled: boolean
  validated: boolean
  manual: boolean
  context: boolean
  console_management: boolean
  approved: boolean
  management_enabled: boolean
  phase: 'not_enrolled' | 'pending_approval' | 'approved' | 'management_enabled'
}

export interface EnrollmentPreferences {
  disable_context: boolean
}

export interface ScenarioItem {
  name: string
  local_version?: string
  local_path?: string
  description?: string
  utf8_status?: string
  status?: string
  version?: string
}

export interface ServiceInfo {
  name: string
  running: boolean
  status?: string
  id?: string
}

export interface AlertSource {
  cn?: string        // ISO country code (e.g., "FR", "US")
  as_name?: string   // Autonomous System name
  as_number?: string // AS number
  ip?: string
  range?: string
  latitude?: number
  longitude?: number
  scope?: string
  value?: string
}

export interface AlertEvent {
  timestamp: string
  meta?: Record<string, string>[]
  [key: string]: unknown
}

export interface CrowdSecAlert {
  id: number
  scenario: string
  scope: string
  value: string
  origin: string
  type?: string
  events_count?: number
  start_at: string
  stop_at?: string
  capacity?: number
  leakspeed?: string
  simulated?: boolean
  message?: string
  decisions?: Decision[]
  source?: AlertSource
  events?: AlertEvent[]
}

export interface AxiosErrorResponse {
  response?: {
    data?: {
      error?: string
    }
  }
}

export interface Allowlist {
  name: string
  description: string
  created_at?: string
}

export interface AllowlistEntry {
  value: string
  created_at: string
  expiration: string
}

export interface AllowlistCreateRequest {
  name: string
  description: string
}

export interface AllowlistAddEntriesRequest {
  allowlist_name: string
  values: string[]
  expiration?: string
  description?: string
}

export interface AllowlistRemoveEntriesRequest {
  allowlist_name: string
  values: string[]
}

export interface AllowlistInspectResponse {
  name: string
  description: string
  items: AllowlistEntry[]  // CrowdSec uses "items", not "entries"
  created_at: string
  updated_at: string
  count: number  // Computed by backend
}

export interface AllowlistImportResult {
  total_input: number
  imported: number
  skipped_invalid: number
  skipped_private: number
  skipped_duplicates: number
}

export interface DecisionFilters {
  since?: string
  until?: string
  type?: string
  scope?: string
  origin?: string
  value?: string
  scenario?: string
  ip?: string
  range?: string
  includeAll?: boolean
}

export interface AlertFilters {
  since?: string
  until?: string
  ip?: string
  range?: string
  scope?: string
  value?: string
  scenario?: string
  type?: string
  origin?: string
  includeAll?: boolean
}

export interface HistoryConfig {
  retention_days: number
  updated_at?: string
}

export interface DecisionHistoryRecord {
  id: number
  dedupe_key: string
  decision_id: number
  alert_id: number
  origin: string
  type: string
  scope: string
  value: string
  duration: string
  scenario: string
  created_at: string
  until?: string
  is_stale: boolean
  first_seen_at: string
  last_seen_at: string
  stale_at?: string
  last_snapshot_at: string
}

export interface AlertHistoryRecord {
  id: number
  dedupe_key: string
  alert_id: number
  scenario: string
  scope: string
  value: string
  origin: string
  type?: string
  events_count: number
  start_at?: string
  stop_at?: string
  is_stale: boolean
  first_seen_at: string
  last_seen_at: string
  stale_at?: string
  last_snapshot_at: string
}

export interface RepeatedOffender {
  value: string
  scope: string
  hit_count: number
  window_days: number
  first_decision_at: string
  last_decision_at: string
  last_notified_at?: string
}

export interface HostInfo {
  id: string
  endpoint: string
  is_local: boolean
  connected: boolean
  error?: string
  is_default: boolean
}

export interface StructuredLogEntry {
  timestamp: string
  level: string
  source: string
  message: string
  fields?: Record<string, string>
  raw: string
}

// History re-insertion types
export interface ReapplyDecisionRequest {
  id: number
  type: string      // "ban" | "captcha"
  duration: string  // e.g. "24h", "7d"
  reason?: string
}

export interface BulkReapplyDecisionsRequest {
  ids: number[]
  type: string
  duration: string
  reason?: string
}

export interface BulkReapplyResult {
  succeeded: number
  failed: number
  errors?: string[]
}

export interface HistoryStats {
  total_decisions: number
  active_decisions: number
  total_alerts: number
  active_alerts: number
  repeated_offender_count: number
}
