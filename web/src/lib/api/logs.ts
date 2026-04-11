import { apiClient } from './client'
import type { ApiResponse, StructuredLogEntry } from './types'

export const logsAPI = {
  getCrowdSec: (tail: string = '100') =>
    apiClient.get<ApiResponse<{ logs: string }>>('/logs/crowdsec', { params: { tail } }),

  getService: (service: string, tail: string = '100') =>
    apiClient.get<ApiResponse<{ logs: string; service: string }>>(`/logs/${service}`, { params: { tail } }),

  // WebSocket stream is handled separately
  getStreamUrl: (service: string) =>
    `/api/logs/stream/${service}`,
}

export const structuredLogsAPI = {
  get: (service: string, tail: string = '200', level?: string) =>
    apiClient.get<ApiResponse<{ entries: StructuredLogEntry[]; count: number; service: string }>>(
      `/logs/structured/${service}`,
      { params: { tail, ...(level ? { level } : {}) } }
    ),
}
