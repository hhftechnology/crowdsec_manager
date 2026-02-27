import { apiClient } from './client'
import type { ApiResponse, Backup, BackupRequest, RestoreRequest } from './types'

export const backupAPI = {
  list: () =>
    apiClient.get<ApiResponse<Backup[]>>('/backup/list'),

  create: (data: BackupRequest) =>
    apiClient.post<ApiResponse<Backup>>('/backup/create', data),

  restore: (data: RestoreRequest) =>
    apiClient.post<ApiResponse>('/backup/restore', data),

  delete: (id: string) =>
    apiClient.delete<ApiResponse>(`/backup/${id}`),

  cleanup: () =>
    apiClient.post<ApiResponse>('/backup/cleanup'),

  getLatest: () =>
    apiClient.get<ApiResponse<Backup>>('/backup/latest'),
}
