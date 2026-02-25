import { apiClient } from './client'
import type {
  ApiResponse,
  Bouncer,
  Decision,
  CrowdSecAlert,
  EnrollRequest,
  ConsoleStatus,
  EnrollmentPreferences,
  AddDecisionRequest,
  DeleteDecisionRequest,
  DecisionFilters,
  AlertFilters,
} from './types'

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
    apiClient.get<ApiResponse<ConsoleStatus>>('/crowdsec/status'),

  finalizeEnrollment: () =>
    apiClient.post<ApiResponse<ConsoleStatus>>('/crowdsec/enroll/finalize'),

  getEnrollmentPreferences: () =>
    apiClient.get<ApiResponse<EnrollmentPreferences>>('/crowdsec/enroll/preferences'),

  updateEnrollmentPreferences: (data: EnrollmentPreferences) =>
    apiClient.put<ApiResponse<EnrollmentPreferences>>('/crowdsec/enroll/preferences', data),

  getAlertsAnalysis: (filters: AlertFilters) =>
    apiClient.get<ApiResponse<{ alerts: CrowdSecAlert[]; count: number }>>('/crowdsec/alerts/analysis', { params: filters }),

  inspectAlert: (id: number) =>
    apiClient.get<ApiResponse<CrowdSecAlert>>(`/crowdsec/alerts/${id}`),

  deleteAlert: (id: number) =>
    apiClient.delete<ApiResponse>(`/crowdsec/alerts/${id}`),

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
