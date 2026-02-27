import { apiClient } from './client'
import type { ApiResponse, ServiceActionRequest, ServiceInfo } from './types'

export const servicesAPI = {
  verify: () =>
    apiClient.get<ApiResponse<ServiceInfo[]>>('/services/verify'),

  shutdown: () =>
    apiClient.post<ApiResponse>('/services/shutdown'),

  action: (data: ServiceActionRequest) =>
    apiClient.post<ApiResponse>('/services/action', data),
}
