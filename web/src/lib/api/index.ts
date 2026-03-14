// Barrel export - re-exports everything from all API modules

// Client and host selection
export { apiClient, setSelectedHost, getSelectedHost } from './client'

// All types
export type {
  ApiResponse,
  Container,
  HealthStatus,
  Decision,
  AddDecisionRequest,
  DeleteDecisionRequest,
  Bouncer,
  IPInfo,
  WhitelistRequest,
  Backup,
  BackupRequest,
  RestoreRequest,
  UpdateRequest,
  ImageTags,
  LogEntry,
  LogStats,
  IPCount,
  Scenario,
  ScenarioSetupRequest,
  CaptchaSetupRequest,
  CaptchaStatus,
  CronJobRequest,
  Metric,
  TraefikIntegration,
  DiagnosticResult,
  UnbanRequest,
  ServiceActionRequest,
  EnrollRequest,
  ConsoleStatus,
  EnrollmentPreferences,
  ScenarioItem,
  CronJob,
  ServiceInfo,
  CrowdSecAlert,
  AxiosErrorResponse,
  ConfigPathRequest,
  ConfigPathResponse,
  Allowlist,
  AllowlistEntry,
  AllowlistCreateRequest,
  AllowlistAddEntriesRequest,
  AllowlistRemoveEntriesRequest,
  AllowlistInspectResponse,
  ServiceUpdateStatus,
  DecisionFilters,
  AlertFilters,
  HostInfo,
  StructuredLogEntry,
  HistoryConfig,
  DecisionHistoryRecord,
  AlertHistoryRecord,
  RepeatedOffender,
} from './types'

// Domain API namespaces
export { healthAPI } from './health'
export { ipAPI } from './ip'
export { whitelistAPI } from './whitelist'
export { allowlistAPI } from './allowlist'
export { scenariosAPI } from './scenarios'
export { captchaAPI } from './captcha'
export { logsAPI, structuredLogsAPI } from './logs'
export { backupAPI } from './backup'
export { cronAPI } from './cron'
export { servicesAPI } from './services'
export { crowdsecAPI } from './crowdsec'
export { traefikAPI } from './traefik'
export { updateAPI } from './update'
export { hostsAPI } from './hosts'
export { terminalAPI } from './terminal'
export { eventsAPI } from './events'
export { configValidationAPI } from './config-validation'
export type { ConfigSnapshot, ConfigValidationResult, ConfigValidationReport } from './config-validation'
export { profilesAPI } from './profiles'
export { hubAPI } from './hub'
export type {
  HubCategoryKey,
  HubCategory,
  HubCategoryItem,
  HubCategoryItemsResponse,
  HubCategoryActionRequest,
  HubManualApplyRequest,
  HubPreference,
  HubOperationRecord,
} from './hub'
export { simulationAPI } from './simulation'
export type { SimulationStatus, SimulationToggleRequest } from './simulation'
export { notificationsAPI } from './notifications'
export type { NotificationConfig } from './notifications'
export type { FeatureDetectionResult, FeatureConfig, StepResult } from './types'
