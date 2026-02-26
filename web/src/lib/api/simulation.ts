import { apiClient } from './client'
import type { ApiResponse } from './types'

export interface SimulationStatus {
  global: boolean
  exclusions?: string[]
}

export interface SimulationToggleRequest {
  scenario: string
  enabled: boolean
}

export const simulationAPI = {
  getStatus: () =>
    apiClient.get<ApiResponse<SimulationStatus>>('/simulation/status'),

  toggle: (data: SimulationToggleRequest) =>
    apiClient.post<ApiResponse<null>>('/simulation/toggle', data),
}
