import { apiClient } from './client'
import type { ApiResponse, TraefikIntegration, ConfigPathRequest, ConfigPathResponse } from './types'

export const traefikAPI = {
  checkIntegration: () =>
    apiClient.get<ApiResponse<TraefikIntegration>>('/traefik/integration'),

  getConfig: () =>
    apiClient.get<ApiResponse<{ static: string; dynamic: string }>>('/traefik/config'),

  getConfigPath: () =>
    apiClient.get<ApiResponse<ConfigPathResponse>>('/traefik/config-path'),

  setConfigPath: (data: ConfigPathRequest) =>
    apiClient.post<ApiResponse>('/traefik/config-path', data),
}
