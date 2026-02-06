import axios from 'axios'

/**
 * Shared axios instance for all API domain clients.
 * Configured with base URL, default headers, and error interceptor.
 */
export const apiClient = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000, // 10 second timeout
})

// Add response interceptor for better error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error.message)

    // If it's a network error (backend not available), provide a user-friendly message
    if (error.code === 'ECONNREFUSED' || error.code === 'ERR_NETWORK' || !error.response) {
      error.message = 'Backend server is not available. Please ensure the CrowdSec Manager backend is running on port 8080.'
    }

    return Promise.reject(error)
  }
)

// ─── Shared TypeScript Interfaces ────────────────────────────────────────────

/** Standard API response envelope matching backend dto.Response */
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

export interface Bouncer {
  name: string
  ip_address: string
  valid: boolean
  revoked?: boolean
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

export interface ImageTags {
  pangolin: string
  gerbil: string
  traefik: string
  crowdsec?: string
}
