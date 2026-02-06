import { apiClient, type ApiResponse, type TraefikIntegration } from './client'

export interface ConfigPathRequest {
  dynamic_config_path: string
}

export interface ConfigPathResponse {
  dynamic_config_path: string
}

/**
 * @deprecated All Traefik-specific endpoints are deprecated.
 * Use proxyAPI for proxy-generic operations instead.
 */
export const traefikAPI = {
  /** @deprecated Use proxyAPI.getCurrent() */
  checkIntegration: () =>
    apiClient.get<ApiResponse<TraefikIntegration>>('/traefik/integration'),

  /** @deprecated Use proxyAPI.getCurrent() */
  getConfig: () =>
    apiClient.get<ApiResponse<{ static: string; dynamic: string }>>('/traefik/config'),

  /** @deprecated Use proxyAPI.getCurrent() */
  getConfigPath: () =>
    apiClient.get<ApiResponse<ConfigPathResponse>>('/traefik/config-path'),

  /** @deprecated Use proxyAPI.configure() */
  setConfigPath: (data: ConfigPathRequest) =>
    apiClient.post<ApiResponse>('/traefik/config-path', data),
}
