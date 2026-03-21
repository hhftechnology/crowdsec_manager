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
  HistoryConfig,
  DecisionHistoryRecord,
  AlertHistoryRecord,
  RepeatedOffender,
  ReapplyDecisionRequest,
  BulkReapplyDecisionsRequest,
  BulkReapplyResult,
  HistoryStats,
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

  getDecisionsSummary: () =>
    apiClient.get<ApiResponse<{ count: number; types: Record<string, number>; scenarios: Record<string, number> }>>('/crowdsec/decisions', { params: { summary: 'true' } }),

  getDecisionsAnalysis: (filters: DecisionFilters) =>
    apiClient.get<ApiResponse<{ decisions: Decision[]; count: number }>>('/crowdsec/decisions/analysis', { params: filters }),

  getDecisionHistory: (params?: { stale?: boolean; value?: string; scenario?: string; since?: string; limit?: number; offset?: number }) =>
    apiClient.get<ApiResponse<{ decisions: DecisionHistoryRecord[]; count: number; total: number }>>('/crowdsec/decisions/history', { params }),

  getRepeatedOffenders: () =>
    apiClient.get<ApiResponse<{ offenders: RepeatedOffender[]; count: number }>>('/crowdsec/decisions/repeated-offenders'),

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

  getAlertHistory: (params?: { stale?: boolean; value?: string; scenario?: string; since?: string; limit?: number; offset?: number }) =>
    apiClient.get<ApiResponse<{ alerts: AlertHistoryRecord[]; count: number; total: number }>>('/crowdsec/alerts/history', { params }),

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

  getHistoryConfig: () =>
    apiClient.get<ApiResponse<HistoryConfig>>('/crowdsec/history/config'),

  updateHistoryConfig: (retentionDays: number) =>
    apiClient.put<ApiResponse<HistoryConfig>>('/crowdsec/history/config', { retention_days: retentionDays }),

  getHistoryStats: () =>
    apiClient.get<ApiResponse<HistoryStats>>('/crowdsec/history/stats'),

  reapplyDecision: (data: ReapplyDecisionRequest) =>
    apiClient.post<ApiResponse<{ message: string }>>('/crowdsec/decisions/history/reapply', data),

  bulkReapplyDecisions: (data: BulkReapplyDecisionsRequest) =>
    apiClient.post<ApiResponse<BulkReapplyResult>>('/crowdsec/decisions/history/bulk-reapply', data),
}
