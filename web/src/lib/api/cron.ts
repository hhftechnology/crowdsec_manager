import { apiClient, type ApiResponse } from './client'

export interface CronJobRequest {
  schedule: string
  task: string
}

export const cronAPI = {
  setup: (data: CronJobRequest) =>
    apiClient.post<ApiResponse>('/cron/setup', data),

  list: () =>
    apiClient.get<ApiResponse<any[]>>('/cron/list'),

  delete: (id: string) =>
    apiClient.delete<ApiResponse>(`/cron/${id}`),
}
