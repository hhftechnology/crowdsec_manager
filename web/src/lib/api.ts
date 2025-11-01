import axios from 'axios'

// API Base Configuration
const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
})

// TypeScript Interfaces matching backend models
export interface ApiResponse<T = any> {
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
  origin: string
  type: string
  scope: string
  value: string
  duration: string
  scenario: string
  created_at: string
}

export interface Bouncer {
  name: string
  ip_address: string
  valid: boolean
  last_pull: string
  type: string
  version: string
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
  description: string
  expiration: string
  expires_at?: string
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
  entries: AllowlistEntry[]
  count: number
}

// =============================================================================
// 1. HEALTH & DIAGNOSTICS (2 endpoints)
// =============================================================================

export const healthAPI = {
  checkStack: () =>
    api.get<ApiResponse<HealthStatus>>('/health/stack'),

  completeDiagnostics: () =>
    api.get<ApiResponse<DiagnosticResult>>('/health/complete'),
}

// =============================================================================
// 2. IP MANAGEMENT (4 endpoints)
// =============================================================================

export const ipAPI = {
  getPublicIP: () =>
    api.get<ApiResponse<{ ip: string }>>('/ip/public'),

  isBlocked: (ip: string) =>
    api.get<ApiResponse<{ ip: string; blocked: boolean; details: string }>>(`/ip/blocked/${ip}`),

  checkSecurity: (ip: string) =>
    api.get<ApiResponse<IPInfo>>(`/ip/security/${ip}`),

  unban: (data: UnbanRequest) =>
    api.post<ApiResponse>('/ip/unban', data),
}

// =============================================================================
// 3. WHITELIST MANAGEMENT (7 endpoints)
// =============================================================================

export const whitelistAPI = {
  view: () =>
    api.get<ApiResponse<{ crowdsec: string[]; traefik: string[] }>>('/whitelist/view'),

  whitelistCurrent: () =>
    api.post<ApiResponse<{ ip: string }>>('/whitelist/current'),

  whitelistManual: (data: WhitelistRequest) =>
    api.post<ApiResponse>('/whitelist/manual', data),

  whitelistCIDR: (data: WhitelistRequest) =>
    api.post<ApiResponse>('/whitelist/cidr', data),

  addToCrowdSec: (data: WhitelistRequest) =>
    api.post<ApiResponse>('/whitelist/crowdsec', data),

  addToTraefik: (data: WhitelistRequest) =>
    api.post<ApiResponse>('/whitelist/traefik', data),

  setupComprehensive: (data: WhitelistRequest) =>
    api.post<ApiResponse>('/whitelist/comprehensive', data),
}

// =============================================================================
// 4. SCENARIOS (2 endpoints)
// =============================================================================

export const scenariosAPI = {
  setup: (data: ScenarioSetupRequest) =>
    api.post<ApiResponse>('/scenarios/setup', data),

  list: () =>
    api.get<ApiResponse<{ scenarios: any[] | string }>>('/scenarios/list'),
}

// =============================================================================
// 5. CAPTCHA (2 endpoints)
// =============================================================================

export const captchaAPI = {
  setup: (data: CaptchaSetupRequest) =>
    api.post<ApiResponse>('/captcha/setup', data),

  getStatus: () =>
    api.get<ApiResponse<CaptchaStatus>>('/captcha/status'),
}

// =============================================================================
// 6. LOGS (5 endpoints)
// =============================================================================

export const logsAPI = {
  getCrowdSec: (tail: string = '100') =>
    api.get<ApiResponse<{ logs: string }>>('/logs/crowdsec', { params: { tail } }),

  getTraefik: (tail: string = '100') =>
    api.get<ApiResponse<{ logs: string }>>('/logs/traefik', { params: { tail } }),

  analyzeTraefikAdvanced: (tail: string = '1000') =>
    api.get<ApiResponse<LogStats>>('/logs/traefik/advanced', { params: { tail } }),

  getService: (service: string, tail: string = '100') =>
    api.get<ApiResponse<{ logs: string; service: string }>>(`/logs/${service}`, { params: { tail } }),

  // WebSocket stream is handled separately
  getStreamUrl: (service: string) =>
    `/api/logs/stream/${service}`,
}

// =============================================================================
// 7. BACKUP (6 endpoints)
// =============================================================================

export const backupAPI = {
  list: () =>
    api.get<ApiResponse<Backup[]>>('/backup/list'),

  create: (data: BackupRequest) =>
    api.post<ApiResponse<Backup>>('/backup/create', data),

  restore: (data: RestoreRequest) =>
    api.post<ApiResponse>('/backup/restore', data),

  delete: (id: string) =>
    api.delete<ApiResponse>(`/backup/${id}`),

  cleanup: () =>
    api.post<ApiResponse>('/backup/cleanup'),

  getLatest: () =>
    api.get<ApiResponse<Backup>>('/backup/latest'),
}

// =============================================================================
// 8. UPDATE (3 endpoints)
// =============================================================================

export const updateAPI = {
  getCurrentTags: () =>
    api.get<ApiResponse<ImageTags>>('/update/current-tags'),

  updateWithCrowdSec: (data: UpdateRequest) =>
    api.post<ApiResponse>('/update/with-crowdsec', data),

  updateWithoutCrowdSec: (data: UpdateRequest) =>
    api.post<ApiResponse>('/update/without-crowdsec', data),
}

// =============================================================================
// 9. CRON (3 endpoints)
// =============================================================================

export const cronAPI = {
  setup: (data: CronJobRequest) =>
    api.post<ApiResponse>('/cron/setup', data),

  list: () =>
    api.get<ApiResponse<any[]>>('/cron/list'),

  delete: (id: string) =>
    api.delete<ApiResponse>(`/cron/${id}`),
}

// =============================================================================
// 10. SERVICES (9 endpoints)
// =============================================================================

export const servicesAPI = {
  verify: () =>
    api.get<ApiResponse<any[]>>('/services/verify'),

  shutdown: () =>
    api.post<ApiResponse>('/services/shutdown'),

  action: (data: ServiceActionRequest) =>
    api.post<ApiResponse>('/services/action', data),
}

// =============================================================================
// 11. CROWDSEC SPECIFIC (6 endpoints)
// =============================================================================

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

export const crowdsecAPI = {
  getBouncers: () =>
     api.get<ApiResponse<{ bouncers: Bouncer[]; count: number }>>('/crowdsec/bouncers'),

  getDecisions: () =>
    api.get<ApiResponse<{ decisions: Decision[]; count: number }>>('/crowdsec/decisions'),

  getDecisionsAnalysis: (filters: DecisionFilters) =>
    api.get<ApiResponse<{ decisions: Decision[]; count: number }>>('/crowdsec/decisions/analysis', { params: filters }),

  getMetrics: () =>
    api.get<ApiResponse<{ metrics: string }>>('/crowdsec/metrics'),

  enroll: (data: EnrollRequest) =>
    api.post<ApiResponse<{ output: string }>>('/crowdsec/enroll', data),

  getAlertsAnalysis: (filters: AlertFilters) =>
    api.get<ApiResponse<{ alerts: any[]; count: number }>>('/crowdsec/alerts/analysis', { params: filters }),
}

// =============================================================================
// 12. TRAEFIK SPECIFIC (2 endpoints)
// =============================================================================

export const traefikAPI = {
  checkIntegration: () =>
    api.get<ApiResponse<TraefikIntegration>>('/traefik/integration'),

  getConfig: () =>
    api.get<ApiResponse<{ static: string; dynamic: string }>>('/traefik/config'),

  getConfigPath: () =>
    api.get<ApiResponse<ConfigPathResponse>>('/traefik/config-path'),

  setConfigPath: (data: ConfigPathRequest) =>
    api.post<ApiResponse>('/traefik/config-path', data),
}

// =============================================================================
// 13. ALLOWLIST (6 endpoints)
// =============================================================================

export const allowlistAPI = {
  list: () =>
    api.get<ApiResponse<Allowlist[]>>('/allowlist/list'),

  create: (data: AllowlistCreateRequest) =>
    api.post<ApiResponse<Allowlist>>('/allowlist/create', data),

  inspect: (name: string) =>
    api.get<ApiResponse<AllowlistInspectResponse>>(`/allowlist/inspect/${name}`),

  addEntries: (data: AllowlistAddEntriesRequest) =>
    api.post<ApiResponse>('/allowlist/add', data),

  removeEntries: (data: AllowlistRemoveEntriesRequest) =>
    api.post<ApiResponse>('/allowlist/remove', data),

  delete: (name: string) =>
    api.delete<ApiResponse>(`/allowlist/${name}`),
}

// Export default API object with all endpoints organized
export default {
  health: healthAPI,
  ip: ipAPI,
  whitelist: whitelistAPI,
  scenarios: scenariosAPI,
  captcha: captchaAPI,
  logs: logsAPI,
  backup: backupAPI,
  update: updateAPI,
  cron: cronAPI,
  services: servicesAPI,
  crowdsec: crowdsecAPI,
  traefik: traefikAPI,
  allowlist: allowlistAPI,
}

// Total: 51 endpoints
// Health: 2, IP: 4, Whitelist: 7, Scenarios: 2, Captcha: 2, Logs: 5,
// Backup: 6, Update: 3, Cron: 3, Services: 3, CrowdSec: 6, Traefik: 4, Allowlist: 6
