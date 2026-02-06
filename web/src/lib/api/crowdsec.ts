import { apiClient, type ApiResponse, type Decision, type Bouncer } from './client'

export interface AddDecisionRequest {
  ip?: string
  range?: string
  duration?: string
  type?: string
  scope?: string
  value?: string
  reason?: string
}

export interface DeleteDecisionRequest {
  id?: string
  ip?: string
  range?: string
  type?: string
  scope?: string
  value?: string
  scenario?: string
  origin?: string
}

export interface EnrollRequest {
  enrollment_key: string
  name?: string
}

export interface DecisionFilters {
  since?: string
  until?: string
  type?: string
  scope?: string
  origin?: string
  value?: string
  scenario?: string
  ip?: string
  range?: string
  includeAll?: boolean
}

export interface AlertFilters {
  since?: string
  until?: string
  ip?: string
  range?: string
  scope?: string
  value?: string
  scenario?: string
  type?: string
  origin?: string
  includeAll?: boolean
}

export const crowdsecAPI = {
  getBouncers: () =>
    apiClient.get<ApiResponse<{ bouncers: Bouncer[]; count: number }>>('/crowdsec/bouncers'),

  addBouncer: (name: string) =>
    apiClient.post<ApiResponse<{ name: string; api_key: string }>>('/crowdsec/bouncers', { name }),

  deleteBouncer: (name: string) =>
    apiClient.delete<ApiResponse>(`/crowdsec/bouncers/${name}`),

  getDecisions: () =>
    apiClient.get<ApiResponse<{ decisions: Decision[]; count: number }>>('/crowdsec/decisions'),

  getDecisionsAnalysis: (filters: DecisionFilters) =>
    apiClient.get<ApiResponse<{ decisions: Decision[]; count: number }>>('/crowdsec/decisions/analysis', { params: filters }),

  getMetrics: () =>
    apiClient.get<ApiResponse<{ metrics: string }>>('/crowdsec/metrics'),

  enroll: (data: EnrollRequest) =>
    apiClient.post<ApiResponse<{ output: string }>>('/crowdsec/enroll', data),

  getStatus: () =>
    apiClient.get<ApiResponse<{ enrolled: boolean; validated: boolean; console_management: boolean }>>('/crowdsec/status'),

  enableConsoleManagement: () =>
    apiClient.post<ApiResponse<{ output: string }>>('/crowdsec/console/enable'),

  getAlertsAnalysis: (filters: AlertFilters) =>
    apiClient.get<ApiResponse<{ alerts: any[]; count: number }>>('/crowdsec/alerts/analysis', { params: filters }),

  addDecision: (data: AddDecisionRequest) =>
    apiClient.post<ApiResponse>('/crowdsec/decisions', data),

  deleteDecision: (params: DeleteDecisionRequest) =>
    apiClient.delete<ApiResponse>('/crowdsec/decisions', { params }),

  importDecisions: (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    return apiClient.post<ApiResponse>('/crowdsec/decisions/import', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
  },
}
