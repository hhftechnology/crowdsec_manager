import { apiClient } from './client'
import type { ApiResponse, WhitelistRequest } from './types'

export const whitelistAPI = {
  view: () =>
    apiClient.get<ApiResponse<{ crowdsec: string[]; traefik: string[] }>>('/whitelist/view'),

  whitelistCurrent: () =>
    apiClient.post<ApiResponse<{ ip: string }>>('/whitelist/current'),

  whitelistManual: (data: WhitelistRequest) =>
    apiClient.post<ApiResponse>('/whitelist/manual', data),

  whitelistCIDR: (data: WhitelistRequest) =>
    apiClient.post<ApiResponse>('/whitelist/cidr', data),

  addToCrowdSec: (data: WhitelistRequest) =>
    apiClient.post<ApiResponse>('/whitelist/crowdsec', data),

  addToTraefik: (data: WhitelistRequest) =>
    apiClient.post<ApiResponse>('/whitelist/traefik', data),

  setupComprehensive: (data: WhitelistRequest) =>
    apiClient.post<ApiResponse>('/whitelist/comprehensive', data),

  remove: (data: { ip: string; remove_from_crowdsec: boolean; remove_from_traefik: boolean }) =>
    apiClient.delete<ApiResponse>('/whitelist/remove', { data }),
}
