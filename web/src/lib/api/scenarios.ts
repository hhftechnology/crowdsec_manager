import { apiClient } from './client'
import type { ApiResponse, ScenarioSetupRequest, ScenarioItem } from './types'

export const scenariosAPI = {
  setup: (data: ScenarioSetupRequest) =>
    apiClient.post<ApiResponse>('/scenarios/setup', data),

  list: () =>
    apiClient.get<ApiResponse<{ scenarios: ScenarioItem[] | string }>>('/scenarios/list'),
}
