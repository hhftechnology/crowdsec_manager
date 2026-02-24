import { apiClient } from './client'
import type { ApiResponse } from './types'

export interface HubItem {
  name: string
  status: string
  version: string
  local_version?: string
  local_path?: string
  description?: string
  author?: string
}

export interface HubActionRequest {
  name: string
  type: 'scenarios' | 'parsers' | 'collections' | 'postoverflows'
}

export const hubAPI = {
  list: () =>
    apiClient.get<ApiResponse<HubItem[]>>('/hub/list'),

  install: (data: HubActionRequest) =>
    apiClient.post<ApiResponse<null>>('/hub/install', data),

  remove: (data: HubActionRequest) =>
    apiClient.post<ApiResponse<null>>('/hub/remove', data),

  upgradeAll: () =>
    apiClient.post<ApiResponse<null>>('/hub/upgrade'),
}
