// Types and API helpers for the Traefik / CrowdSec log dashboards.
// Keeps the larger types.ts untouched and lets the API client tree-shake
// these types out of pages that don't use them.
import { apiClient } from './client'
import type { ApiResponse } from './types'

export type DashboardRange = '5m' | '1h' | '6h' | '24h' | '7d' | 'all'

export const DASHBOARD_RANGES: DashboardRange[] = ['5m', '1h', '6h', '24h', '7d', 'all']

export interface NameValue {
  name: string
  value: number
}

export interface IPStat {
  ip: string
  count: number
  country?: string
  lat?: number
  lng?: number
}

export interface TraefikBucket {
  t: string
  total: number
  c2xx: number
  c3xx: number
  c4xx: number
  c5xx: number
}

export interface TraefikRecentError {
  t: string
  ip: string
  method?: string
  path?: string
  status: number
  duration_ms?: number
}

export interface TraefikServiceDetail {
  name: string
  requests: number
  avg_duration_ms: number
  error_rate: number
}

export interface TraefikPathDetail {
  path: string
  method: string
  count: number
  avg_duration_ms: number
}

export interface TraefikRouterDetail {
  name: string
  requests: number
  avg_duration_ms: number
  service?: string
}

export interface TraefikDashboard {
  range: DashboardRange
  format: 'json' | 'clf'
  generated_at: string
  total_requests: number
  unique_ips: number
  avg_duration_ms: number | null
  p95_response_time_ms: number | null
  p99_response_time_ms: number | null
  error_rate: number
  series: TraefikBucket[]
  status_codes: NameValue[]
  methods: NameValue[]
  top_ips: IPStat[]
  top_hosts: NameValue[]
  top_routers: TraefikRouterDetail[]
  top_paths: TraefikPathDetail[]
  top_services: TraefikServiceDetail[]
  top_addresses: NameValue[]
  user_agents: NameValue[]
  slowest_endpoints: NameValue[]
  tls_versions: NameValue[]
  recent_errors: TraefikRecentError[]
  system?: SystemStats
}

export interface SystemStats {
  cpu: CPUStats
  memory: MemoryStats
  disk: DiskStats
}

export interface CPUStats {
  usage_percent: number
  cores: number
  model: string
}

export interface MemoryStats {
  total: number
  used: number
  available: number
  used_percent: number
}

export interface DiskStats {
  total: number
  used: number
  free: number
  used_percent: number
}

export interface CrowdSecBucket {
  t: string
  alerts: number
  decisions: number
  errors: number
}

export interface AcquisitionStat {
  source: string
  lines: number
}

export interface CrowdSecActivity {
  t: string
  level: string
  source?: string
  message: string
}

export interface CrowdSecDashboard {
  range: DashboardRange
  generated_at: string
  total_events: number
  decisions: number
  alerts: number
  parser_errors: number
  series: CrowdSecBucket[]
  top_scenarios: NameValue[]
  top_source_ips: IPStat[]
  top_origins: NameValue[]
  top_decision_types: NameValue[]
  acquisition: AcquisitionStat[]
  bouncer_activity: CrowdSecActivity[]
  recent_errors: CrowdSecActivity[]
}

export const dashboardAPI = {
  getTraefik: (range: DashboardRange) =>
    apiClient.get<ApiResponse<TraefikDashboard>>('/logs/traefik/dashboard', {
      params: { range },
    }),
  getCrowdSec: (range: DashboardRange) =>
    apiClient.get<ApiResponse<CrowdSecDashboard>>('/logs/crowdsec/dashboard', {
      params: { range },
    }),
}
