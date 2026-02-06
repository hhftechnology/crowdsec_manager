import { apiClient, type ApiResponse } from './client'

export interface ProxyTypeInfo {
  type: string
  name: string
  description: string
  features: string[]
  experimental?: boolean
}

export interface ProxyCurrentInfo {
  type: string
  name: string
  running: boolean
  connected: boolean
  container_name: string
  supported_features: string[]
}

export interface ProxyFeatureInfo {
  feature: string
  available: boolean
  description: string
}

export interface ProxyConfigRequest {
  proxy_type: string
  container_name?: string
  config_paths?: Record<string, string>
  custom_settings?: Record<string, string>
}

export const proxyAPI = {
  getTypes: () =>
    apiClient.get<ApiResponse<{ proxy_types: ProxyTypeInfo[] }>>('/proxy/types'),

  getCurrent: () =>
    apiClient.get<ApiResponse<ProxyCurrentInfo>>('/proxy/current'),

  getFeatures: () =>
    apiClient.get<ApiResponse<{ features: ProxyFeatureInfo[] }>>('/proxy/features'),

  configure: (data: ProxyConfigRequest) =>
    apiClient.post<ApiResponse>('/proxy/configure', data),

  checkHealth: () =>
    apiClient.get<ApiResponse<{ status: string; details: any }>>('/proxy/health'),

  getBouncerStatus: () =>
    apiClient.get<ApiResponse<{ supported: boolean; configured: boolean; status: any; reason?: string }>>('/proxy/bouncer/status'),

  validateBouncerConfiguration: () =>
    apiClient.post<ApiResponse>('/proxy/bouncer/validate'),
}
