import { apiClient } from './client'
import type { ApiResponse, IPInfo, UnbanRequest } from './types'

export const ipAPI = {
  getPublicIP: () =>
    apiClient.get<ApiResponse<{ ip: string }>>('/ip/public'),

  isBlocked: (ip: string) =>
    apiClient.get<ApiResponse<{ ip: string; blocked: boolean; details: string }>>(`/ip/blocked/${ip}`),

  checkSecurity: (ip: string) =>
    apiClient.get<ApiResponse<IPInfo>>(`/ip/security/${ip}`),

  unban: (data: UnbanRequest) =>
    apiClient.post<ApiResponse>('/ip/unban', data),
}
