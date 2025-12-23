// Validation types matching backend structures

export type ValidationSeverity = 'error' | 'warning' | 'info'
export type ValidationStatus = 'valid' | 'warning' | 'error'
export type LayerType = 'host' | 'volume' | 'container' | 'env'
export type SuggestionType =
  | 'create_file'
  | 'create_directory'
  | 'fix_path'
  | 'add_volume'
  | 'update_env'
  | 'remove_env'
  | 'start_container'
  | 'fix_permissions'

export interface ValidationResult {
  valid: boolean
  proxy_type: string
  timestamp: string
  summary: ValidationSummary
  env_vars: EnvVarValidation
  layers: LayerValidations
  suggestions: Suggestion[]
  errors: ValidationError[]
  warnings: ValidationWarning[]
}

export interface ValidationSummary {
  total_checks: number
  passed_checks: number
  failed_checks: number
  warning_checks: number
  overall_status: ValidationStatus
  ready_to_deploy: boolean
}

export interface EnvVarValidation {
  required: EnvVarCheck[]
  optional: EnvVarCheck[]
  custom?: EnvVarCheck[]
  all: EnvVarCheck[]
}

export interface EnvVarCheck {
  name: string
  value: string
  required: boolean
  valid: boolean
  set: boolean
  default: string
  description: string
  error?: string
  suggestion?: string
  severity: ValidationSeverity
  impact?: string
}

export interface LayerValidations {
  host_paths: LayerValidation
  volume_mappings: LayerValidation
  container_paths: LayerValidation
}

export interface LayerValidation {
  status: ValidationStatus
  checks: ValidationCheck[]
}

export interface ValidationCheck {
  layer: LayerType
  path: string
  type: string
  exists: boolean
  accessible: boolean
  expected_location: string
  actual_location?: string
  valid: boolean
  error?: string
  suggestion?: string
  severity: ValidationSeverity
  details?: Record<string, string>
}

export interface ValidationError {
  layer: LayerType
  code: string
  message: string
  path?: string
  env_var?: string
  suggestion?: string
  impact?: string
}

export interface ValidationWarning {
  layer: LayerType
  code: string
  message: string
  path?: string
  env_var?: string
  suggestion?: string
  impact?: string
}

export interface Suggestion {
  id: string
  type: SuggestionType
  severity: ValidationSeverity
  title: string
  message: string
  impact: string
  command?: string
  env_update?: EnvUpdate
  volume_update?: VolumeUpdate
  file_create?: FileCreate
  auto_fixable: boolean
  applied_at?: string
}

export interface EnvUpdate {
  key: string
  current_value: string
  suggested_value: string
  reason: string
}

export interface VolumeUpdate {
  host_path: string
  container_path: string
  mode: string
  service: string
  reason: string
}

export interface FileCreate {
  path: string
  type: string
  content?: string
  permissions: string
  reason: string
}

export interface ProxyRequirements {
  proxy_type: string
  required_env_vars: string[]
  optional_env_vars: string[]
  required_paths: PathRequirement[]
  optional_paths: PathRequirement[]
  required_volumes: VolumeRequirement[]
  features: string[]
}

export interface PathRequirement {
  env_var: string
  default_path: string
  type: string
  required: boolean
  description: string
  host_path: string
  container_path: string
  feature_needed: string
}

export interface VolumeRequirement {
  host_path: string
  container_path: string
  mode: string
  required: boolean
  description: string
}

export interface ValidationApiResponse<T> {
  success: boolean
  data?: T
  error?: string
}
