import { apiClient, type ApiResponse } from './client'

export interface Scenario {
  name: string
  description: string
  content: string
}

export interface ScenarioSetupRequest {
  scenarios: Scenario[]
}

export const scenariosAPI = {
  setup: (data: ScenarioSetupRequest) =>
    apiClient.post<ApiResponse>('/scenarios/setup', data),

  list: () =>
    apiClient.get<ApiResponse<{ scenarios: any[] | string }>>('/scenarios/list'),
}
