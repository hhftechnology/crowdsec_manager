import { apiClient } from './client'
import type { ApiResponse, CaptchaSetupRequest, CaptchaStatus, FeatureDetectionResult, StepResult } from './types'

export interface CaptchaConfigRequest {
  provider: string
  site_key: string
  secret_key: string
}

export const captchaAPI = {
  setup: (data: CaptchaSetupRequest) =>
    apiClient.post<ApiResponse>('/captcha/setup', data),

  getStatus: () =>
    apiClient.get<ApiResponse<CaptchaStatus>>('/captcha/status'),

  detect: () =>
    apiClient.get<ApiResponse<FeatureDetectionResult>>('/captcha/detect'),

  saveConfig: (data: CaptchaConfigRequest) =>
    apiClient.post<ApiResponse<{ provider: string; saved: boolean; next_steps: string[] }>>('/captcha/config', data),

  applyConfig: (step?: number) =>
    apiClient.post<ApiResponse<{ steps: StepResult[]; applied: boolean; provider: string }>>(
      `/captcha/apply${step ? `?step=${step}` : ''}`
    ),
}
