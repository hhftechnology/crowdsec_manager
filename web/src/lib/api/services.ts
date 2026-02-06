import { apiClient, type ApiResponse } from './client'

export interface ServiceActionRequest {
  service: string
  action: 'start' | 'stop' | 'restart'
}

export const servicesAPI = {
  verify: () =>
    apiClient.get<ApiResponse<any[]>>('/services/verify'),

  shutdown: () =>
    apiClient.post<ApiResponse>('/services/shutdown'),

  action: (data: ServiceActionRequest) =>
    apiClient.post<ApiResponse>('/services/action', data),
}
