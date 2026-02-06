import { apiClient } from './client'
import type {
  ValidationResult,
  ValidationApiResponse,
  EnvVarValidation,
  LayerValidation,
  ProxyRequirements,
  Suggestion,
} from '../validation-types'

export const validationAPI = {
  // Complete validation
  validateComplete: () =>
    apiClient.get<ValidationApiResponse<ValidationResult>>('/config/validate/complete'),

  // Quick summary
  getSummary: () =>
    apiClient.get<ValidationApiResponse<any>>('/config/summary'),

  // Suggestions
  getSuggestions: () =>
    apiClient.get<ValidationApiResponse<{ suggestions: Suggestion[]; summary: any }>>('/config/suggestions'),

  // Environment variables
  getEnvVars: () =>
    apiClient.get<ValidationApiResponse<Record<string, string>>>('/config/env'),

  validateEnvVars: () =>
    apiClient.post<ValidationApiResponse<EnvVarValidation>>('/config/env/validate'),

  getRequiredEnvVars: (proxyType?: string) =>
    apiClient.get<ValidationApiResponse<any>>(
      proxyType ? `/config/env/required/${proxyType}` : '/config/env/required'
    ),

  // Path validation
  validateHostPaths: () =>
    apiClient.get<ValidationApiResponse<LayerValidation>>('/config/paths/validate/host'),

  validateContainerPaths: () =>
    apiClient.get<ValidationApiResponse<LayerValidation>>('/config/paths/validate/container'),

  testPath: (path: string, type: 'host' | 'container') =>
    apiClient.post<ValidationApiResponse<any>>('/config/paths/test', { path, type }),

  // Volume validation
  validateVolumes: () =>
    apiClient.get<ValidationApiResponse<LayerValidation>>('/config/volumes/validate'),

  // Requirements
  getRequirements: (proxyType?: string) =>
    apiClient.get<ValidationApiResponse<ProxyRequirements | Record<string, ProxyRequirements>>>(
      proxyType ? `/config/requirements/${proxyType}` : '/config/requirements'
    ),

  // Export
  exportEnvFile: () =>
    apiClient.get('/config/export/env', { responseType: 'blob' }),
}
