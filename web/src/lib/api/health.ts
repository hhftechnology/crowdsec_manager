import { apiClient, type ApiResponse, type HealthStatus, type DiagnosticResult } from './client'

export const healthAPI = {
  checkStack: () =>
    apiClient.get<ApiResponse<HealthStatus>>('/health/stack'),

  crowdsecHealth: () =>
    apiClient.get<ApiResponse>('/health/crowdsec'),

  completeDiagnostics: () =>
    apiClient.get<ApiResponse<DiagnosticResult>>('/health/complete'),
}
