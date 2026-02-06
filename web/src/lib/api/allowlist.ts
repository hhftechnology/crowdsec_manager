import { apiClient, type ApiResponse } from './client'

export interface Allowlist {
  name: string
  description: string
  created_at?: string
}

export interface AllowlistEntry {
  value: string
  created_at: string
  expiration: string
}

export interface AllowlistCreateRequest {
  name: string
  description: string
}

export interface AllowlistAddEntriesRequest {
  allowlist_name: string
  values: string[]
  expiration?: string
  description?: string
}

export interface AllowlistRemoveEntriesRequest {
  allowlist_name: string
  values: string[]
}

export interface AllowlistInspectResponse {
  name: string
  description: string
  items: AllowlistEntry[]
  created_at: string
  updated_at: string
  count: number
}

export const allowlistAPI = {
  list: () =>
    apiClient.get<ApiResponse<{ allowlists: Allowlist[]; count: number }>>('/allowlist/list'),

  create: (data: AllowlistCreateRequest) =>
    apiClient.post<ApiResponse<Allowlist>>('/allowlist/create', data),

  inspect: (name: string) =>
    apiClient.get<ApiResponse<AllowlistInspectResponse>>(`/allowlist/inspect/${name}`),

  addEntries: (data: AllowlistAddEntriesRequest) =>
    apiClient.post<ApiResponse>('/allowlist/add', data),

  removeEntries: (data: AllowlistRemoveEntriesRequest) =>
    apiClient.post<ApiResponse>('/allowlist/remove', data),

  delete: (name: string) =>
    apiClient.delete<ApiResponse>(`/allowlist/${name}`),
}
