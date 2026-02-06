import { apiClient, type ApiResponse } from './client'

export interface CaptchaSetupRequest {
  provider: string
  site_key: string
  secret_key: string
}

export interface CaptchaStatus {
  configured: boolean
  configSaved: boolean
  provider?: string
  detectedProvider?: string
  savedProvider?: string
  captchaHTMLExists: boolean
  hasHTMLPath: boolean
  implemented: boolean
}

export const captchaAPI = {
  setup: (data: CaptchaSetupRequest) =>
    apiClient.post<ApiResponse>('/captcha/setup', data),

  getStatus: () =>
    apiClient.get<ApiResponse<CaptchaStatus>>('/captcha/status'),
}
