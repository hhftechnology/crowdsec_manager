import { apiClient } from './client'
import type { ApiResponse } from './types'

export interface ConfigSnapshot {
  id: number
  config_type: string
  file_path: string
  content: string
  content_hash: string
  source: string
  created_at: string
  updated_at: string
}

export interface ConfigValidationResult {
  config_type: string
  file_path: string
  status: 'match' | 'drift' | 'missing' | 'no_snapshot'
  message: string
  db_hash?: string
  live_hash?: string
}

export interface ConfigValidationReport {
  timestamp: string
  overall: 'ok' | 'drift_detected' | 'missing_configs'
  results: ConfigValidationResult[]
}

export const configValidationAPI = {
  validate: () =>
    apiClient.get<ApiResponse<ConfigValidationReport>>('/config/validation/validate'),

  getSnapshots: () =>
    apiClient.get<ApiResponse<ConfigSnapshot[]>>('/config/validation/snapshots'),

  snapshotAll: () =>
    apiClient.post<ApiResponse<null>>('/config/validation/snapshot'),

  restore: (type: string) =>
    apiClient.post<ApiResponse<null>>(`/config/validation/restore/${type}`),

  accept: (type: string) =>
    apiClient.post<ApiResponse<null>>(`/config/validation/accept/${type}`),

  deleteSnapshot: (type: string) =>
    apiClient.delete<ApiResponse<null>>(`/config/validation/snapshot/${type}`),
}
