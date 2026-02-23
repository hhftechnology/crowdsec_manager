import { apiClient } from './client'
import type { ApiResponse, CronJobRequest, CronJob } from './types'

export const cronAPI = {
  setup: (data: CronJobRequest) =>
    apiClient.post<ApiResponse>('/cron/setup', data),

  list: () =>
    apiClient.get<ApiResponse<CronJob[]>>('/cron/list'),

  delete: (id: string) =>
    apiClient.delete<ApiResponse>(`/cron/${id}`),
}
