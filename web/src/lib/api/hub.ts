import { apiClient } from './client'
import type { ApiResponse } from './types'

export type HubCategoryKey =
  | 'collections'
  | 'scenarios'
  | 'parsers'
  | 'postoverflows'
  | 'remediations'
  | 'appsec-configs'
  | 'appsec-rules'
  | 'contexts'

export interface HubCategory {
  key: HubCategoryKey
  label: string
  cli_type: string
  container_dir: string
  supports_direct: boolean
}

export interface HubCategoryItem {
  name: string
  status?: string
  version?: string
  local_version?: string
  local_path?: string
  description?: string
  author?: string
}

export interface HubCategoryItemsResponse {
  category: HubCategory
  items?: HubCategoryItem[] | Record<string, unknown> | unknown
  raw_output?: string
}

export interface HubCategoryActionRequest {
  item_name: string
}

export interface HubManualApplyRequest {
  filename: string
  yaml: string
  target_path?: string
}

export interface HubPreference {
  category: HubCategoryKey
  default_mode: 'direct' | 'manual'
  default_yaml_path?: string
  last_item_name?: string
  updated_at?: string
}

export interface HubOperationRecord {
  id: number
  category: HubCategoryKey
  mode: 'direct' | 'manual'
  action: string
  item_name?: string
  yaml_path?: string
  yaml_content?: string
  command?: string
  success: boolean
  output?: string
  error?: string
  created_at?: string
}

export const hubAPI = {
  list: () =>
    apiClient.get<ApiResponse<unknown>>('/hub/list'),

  upgradeAll: () =>
    apiClient.post<ApiResponse<null>>('/hub/upgrade'),

  listCategories: () =>
    apiClient.get<ApiResponse<HubCategory[]>>('/hub/categories'),

  listItems: (category: HubCategoryKey) =>
    apiClient.get<ApiResponse<HubCategoryItemsResponse>>(`/hub/${category}/items`),

  install: (category: HubCategoryKey, data: HubCategoryActionRequest) =>
    apiClient.post<ApiResponse<{ output: string }>>(`/hub/${category}/install`, data),

  remove: (category: HubCategoryKey, data: HubCategoryActionRequest) =>
    apiClient.post<ApiResponse<{ output: string }>>(`/hub/${category}/remove`, data),

  manualApply: (category: HubCategoryKey, data: HubManualApplyRequest) =>
    apiClient.post<ApiResponse<{ path: string; apply_output?: string }>>(`/hub/${category}/manual-apply`, data),

  listPreferences: () =>
    apiClient.get<ApiResponse<HubPreference[]>>('/hub/preferences'),

  getPreference: (category: HubCategoryKey) =>
    apiClient.get<ApiResponse<HubPreference>>(`/hub/preferences/${category}`),

  updatePreference: (category: HubCategoryKey, data: Partial<HubPreference>) =>
    apiClient.put<ApiResponse<HubPreference>>(`/hub/preferences/${category}`, data),

  listHistory: (params?: { category?: string; mode?: string; success?: boolean; limit?: number; offset?: number }) =>
    apiClient.get<ApiResponse<HubOperationRecord[]>>('/hub/history', { params }),

  getHistoryItem: (id: number) =>
    apiClient.get<ApiResponse<HubOperationRecord>>(`/hub/history/${id}`),
}
