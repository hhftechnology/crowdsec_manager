import { apiClient, type ApiResponse } from './client'

export interface DiscordConfig {
  enabled: boolean
  webhook_id: string
  webhook_token: string
  geoapify_key: string
  crowdsec_cti_api_key: string
}

// Note: Full Discord config types are in the backend models.
// Import more specific types as needed from a shared types file.

export const notificationsAPI = {
  getDiscordConfig: () =>
    apiClient.get<ApiResponse<DiscordConfig>>('/notifications/discord'),

  previewDiscordConfig: () =>
    apiClient.get<ApiResponse>('/notifications/discord/preview'),

  updateDiscordConfig: (data: DiscordConfig) =>
    apiClient.post<ApiResponse>('/notifications/discord', data),
}
