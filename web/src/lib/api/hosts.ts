import { apiClient } from './client'
import type { ApiResponse, HostInfo } from './types'

export const hostsAPI = {
  list: () =>
    apiClient.get<ApiResponse<HostInfo[]>>('/hosts/list'),
}
