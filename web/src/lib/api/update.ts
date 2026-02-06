import { apiClient, type ApiResponse } from './client'

export interface UpdateRequest {
  pangolin_tag?: string
  gerbil_tag?: string
  traefik_tag?: string
  crowdsec_tag?: string
  include_crowdsec: boolean
}

export interface ServiceUpdateStatus {
  current_tag: string
  latest_warning: boolean
  update_available: boolean
  error?: string
}

export const updateAPI = {
  checkForUpdates: () =>
    apiClient.get<ApiResponse<Record<string, ServiceUpdateStatus>>>('/update/check'),

  updateWithCrowdSec: (data: UpdateRequest) =>
    apiClient.post<ApiResponse>('/update/with-crowdsec', data),

  updateWithoutCrowdSec: (data: UpdateRequest) =>
    apiClient.post<ApiResponse>('/update/without-crowdsec', data),
}
