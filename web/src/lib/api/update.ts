import { apiClient } from './client'
import type { ApiResponse, UpdateRequest, ServiceUpdateStatus } from './types'

export const updateAPI = {
  checkForUpdates: () =>
    apiClient.get<ApiResponse<Record<string, ServiceUpdateStatus>>>('/update/check'),

  updateWithCrowdSec: (data: UpdateRequest) =>
    apiClient.post<ApiResponse>('/update/with-crowdsec', data),

  updateWithoutCrowdSec: (data: UpdateRequest) =>
    apiClient.post<ApiResponse>('/update/without-crowdsec', data),
}
