import { apiClient, type ApiResponse } from './client'

export interface AddonInfo {
  name: string
  display_name: string
  description: string
  proxy_types: string[]
  required: boolean
  category: string
  status: AddonStatus
  features: string[]
}

export interface AddonStatus {
  name: string
  enabled: boolean
  running: boolean
  container_name: string
  version: string
  health: string
}

export const addonsAPI = {
  list: () =>
    apiClient.get<ApiResponse<{ available_addons: AddonInfo[] }>>('/addons'),

  getStatus: (addon: string) =>
    apiClient.get<ApiResponse<AddonStatus>>(`/addons/${addon}/status`),

  getConfig: (addon: string) =>
    apiClient.get<ApiResponse<any>>(`/addons/${addon}/config`),

  enable: (addon: string, config?: Record<string, any>) =>
    apiClient.post<ApiResponse>(`/addons/${addon}/enable`, { addon, config }),

  disable: (addon: string) =>
    apiClient.post<ApiResponse>(`/addons/${addon}/disable`, { addon }),
}
