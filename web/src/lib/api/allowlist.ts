import { apiClient } from './client'
import type {
  ApiResponse,
  Allowlist,
  AllowlistInspectResponse,
  AllowlistCreateRequest,
  AllowlistAddEntriesRequest,
  AllowlistRemoveEntriesRequest,
} from './types'

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
