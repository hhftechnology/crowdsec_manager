import { apiClient, type ApiResponse } from './client'

export interface WhitelistRequest {
  ip: string
  cidr?: string
  add_to_crowdsec: boolean
  add_to_traefik: boolean // Backward compatibility
  add_to_proxy?: boolean // New generic proxy field
  comprehensive?: boolean
}

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

  /** @deprecated Use addToProxy() instead */
  addToTraefik: (data: WhitelistRequest) =>
    apiClient.post<ApiResponse>('/whitelist/traefik', data),

  /** Generic proxy whitelist endpoint (preferred over addToTraefik) */
  addToProxy: (data: WhitelistRequest) =>
    apiClient.post<ApiResponse>('/whitelist/proxy', data),

  setupComprehensive: (data: WhitelistRequest) =>
    apiClient.post<ApiResponse>('/whitelist/comprehensive', data),
}
