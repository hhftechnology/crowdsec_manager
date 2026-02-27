import { apiClient } from './client'
import type { ApiResponse, FeatureDetectionResult, StepResult } from './types'

export interface NotificationConfig {
  enabled: boolean
  webhook_id: string
  webhook_token: string
  geoapify_key: string
  crowdsec_cti_api_key: string
  crowdsec_restarted?: boolean
  raw_yaml?: string
}

export const notificationsAPI = {
  getDiscordConfig: () =>
    apiClient.get<ApiResponse<NotificationConfig & { config_source?: string; manually_configured?: boolean }>>('/notifications/discord'),

  updateDiscordConfig: (data: NotificationConfig) =>
    apiClient.post<ApiResponse>('/notifications/discord', data),

  previewDiscordConfig: (source: 'default' | 'container') =>
    apiClient.get<ApiResponse<string>>('/notifications/discord/preview', { params: { source } }),

  detect: () =>
    apiClient.get<ApiResponse<FeatureDetectionResult>>('/notifications/discord/detect'),

  saveConfig: (data: NotificationConfig) =>
    apiClient.post<ApiResponse<{ saved: boolean; next_steps: string[] }>>('/notifications/discord/config', data),

  applyConfig: (step?: number) =>
    apiClient.post<ApiResponse<{ steps: StepResult[]; applied: boolean }>>(
      `/notifications/discord/apply${step ? `?step=${step}` : ''}`
    ),
}
