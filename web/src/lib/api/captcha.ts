import { apiClient } from './client'
import type { ApiResponse, CaptchaSetupRequest, CaptchaStatus } from './types'

export const captchaAPI = {
  setup: (data: CaptchaSetupRequest) =>
    apiClient.post<ApiResponse>('/captcha/setup', data),

  getStatus: () =>
    apiClient.get<ApiResponse<CaptchaStatus>>('/captcha/status'),
}
