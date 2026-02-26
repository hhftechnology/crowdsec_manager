import { apiClient } from './client'
import type { ApiResponse } from './types'

export const profilesAPI = {
  get: (useDefault?: boolean) =>
    apiClient.get<ApiResponse<string>>('/profiles', {
      params: useDefault ? { default: 'true' } : undefined,
    }),

  update: (content: string, restart: boolean) =>
    apiClient.post<ApiResponse<null>>('/profiles', { content, restart }),
}
