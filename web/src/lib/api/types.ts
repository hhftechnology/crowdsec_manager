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

export interface IPInfo {
  ip: string
  is_blocked: boolean
  is_whitelisted: boolean
  in_crowdsec: boolean
  in_traefik: boolean
}

export interface WhitelistRequest {
  ip: string
  cidr?: string
  add_to_crowdsec: boolean
  add_to_traefik: boolean
  comprehensive?: boolean
}

export interface Backup {
  id: string
  filename: string
  path: string
  size: number
  created_at: string
}

export interface BackupRequest {
  items?: string[]
  dry_run: boolean
}

export interface RestoreRequest {
  backup_id: string
  confirm: boolean
}

export interface UpdateRequest {
  pangolin_tag?: string
  gerbil_tag?: string
  traefik_tag?: string
  crowdsec_tag?: string
  include_crowdsec: boolean
}

export interface ImageTags {
  pangolin: string
  gerbil: string
  traefik: string
  crowdsec?: string
}

export interface LogEntry {
  timestamp: string
  level: string
  service: string
  message: string
}

export interface LogStats {
  total_lines: number
  top_ips: IPCount[]
  status_codes: Record<string, number>
  http_methods: Record<string, number>
  error_entries: LogEntry[]
}

export interface IPCount {
  ip: string
  count: number
}

export interface Scenario {
  name: string
  description: string
  content: string
}

export interface ScenarioSetupRequest {
  scenarios: Scenario[]
}

export interface CaptchaSetupRequest {
  provider: string
  site_key: string
  secret_key: string
}

export interface CaptchaStatus {
  configured: boolean
  configSaved: boolean
  provider?: string
  detectedProvider?: string
  savedProvider?: string
  captchaHTMLExists: boolean
  hasHTMLPath: boolean
  implemented: boolean
  site_key?: string
  secret_key?: string
  manually_configured?: boolean
}

export interface CronJobRequest {
  schedule: string
  task: string
}

export interface Metric {
  name: string
  value: number
  labels?: Record<string, string>
}

export interface TraefikIntegration {
  middleware_configured: boolean
  config_files: string[]
  lapi_key_found: boolean
  appsec_enabled: boolean
  captcha_enabled: boolean
  captcha_provider?: string
  captcha_html_exists: boolean
}

export interface DiagnosticResult {
  health: HealthStatus
  bouncers: Bouncer[]
  decisions: Decision[]
  traefik_integration: TraefikIntegration
  timestamp: string
}

export interface UnbanRequest {
  ip: string
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

export interface CronJob {
  id: string
  schedule: string
  task: string
  status?: string
  enabled?: boolean
  last_run?: string
  next_run?: string
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

export interface ConfigPathRequest {
  dynamic_config_path: string
}

export interface ConfigPathResponse {
  dynamic_config_path: string
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

export interface ServiceUpdateStatus {
  current_tag: string
  latest_warning: boolean
  update_available: boolean
  error?: string
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

export interface FeatureConfig {
  id: number
  feature: string
  config_json: string
  source: string
  applied: boolean
  applied_at?: string
  created_at: string
  updated_at: string
}

export interface FeatureDetectionResult {
  detected_values: Record<string, unknown>
  sources: Record<string, boolean>
  db_config: FeatureConfig | null
  status: 'not_configured' | 'partially_configured' | 'configured' | 'applied'
}

export interface StepResult {
  step: number
  name: string
  success: boolean
  error?: string
  skipped?: boolean
}
