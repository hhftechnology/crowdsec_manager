import { apiClient } from './client'
import type { ApiResponse, HealthStatus, DiagnosticResult } from './types'

export const healthAPI = {
  checkStack: () =>
    apiClient.get<ApiResponse<HealthStatus>>('/health/stack'),

  crowdsecHealth: () =>
    apiClient.get<ApiResponse>('/health/crowdsec'),

  completeDiagnostics: () =>
    apiClient.get<ApiResponse<DiagnosticResult>>('/health/complete'),
}
