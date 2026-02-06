import { apiClient, type ApiResponse, type LogStats } from './client'

export const logsAPI = {
  getCrowdSec: (tail: string = '100') =>
    apiClient.get<ApiResponse<{ logs: string }>>('/logs/crowdsec', { params: { tail } }),

  /** @deprecated Use getProxy() instead */
  getTraefik: (tail: string = '100') =>
    apiClient.get<ApiResponse<{ logs: string }>>('/logs/traefik', { params: { tail } }),

  /** @deprecated Use analyzeProxy() instead */
  analyzeTraefikAdvanced: (tail: string = '1000') =>
    apiClient.get<ApiResponse<LogStats>>('/logs/traefik/advanced', { params: { tail } }),

  /** Generic proxy log endpoint (preferred over getTraefik) */
  getProxy: (tail: string = '100') =>
    apiClient.get<ApiResponse<{ logs: string }>>('/logs/proxy', { params: { tail } }),

  /** Generic proxy log analysis (preferred over analyzeTraefikAdvanced) */
  analyzeProxy: (tail: string = '1000') =>
    apiClient.get<ApiResponse<LogStats>>('/logs/proxy/analyze', { params: { tail } }),

  getService: (service: string, tail: string = '100') =>
    apiClient.get<ApiResponse<{ logs: string; service: string }>>(`/logs/${service}`, { params: { tail } }),

  // WebSocket stream is handled separately
  getStreamUrl: (service: string) =>
    `/api/logs/stream/${service}`,
}
