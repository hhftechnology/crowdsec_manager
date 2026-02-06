import { apiClient, type ApiResponse } from './client'

export interface Backup {
  id: string
  filename: string
  path: string
  size: number
  created_at: string
}

export interface BackupRequest {
  items?: string[]
  dry_run: boolean
}

export interface RestoreRequest {
  backup_id: string
  confirm: boolean
}

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
