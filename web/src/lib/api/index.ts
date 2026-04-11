// Barrel export - re-exports everything from supported API modules

// Client and host selection
export { apiClient, setSelectedHost, getSelectedHost } from './client'

// Shared types
export type {
  ApiResponse,
  Container,
  HealthStatus,
  Decision,
  AddDecisionRequest,
  DeleteDecisionRequest,
  Bouncer,
  LogEntry,
  Scenario,
  ScenarioSetupRequest,
  Metric,
  DiagnosticResult,
  ServiceActionRequest,
  EnrollRequest,
  ConsoleStatus,
  EnrollmentPreferences,
  ScenarioItem,
  ServiceInfo,
  CrowdSecAlert,
  AxiosErrorResponse,
  Allowlist,
  AllowlistEntry,
  AllowlistCreateRequest,
  AllowlistAddEntriesRequest,
  AllowlistRemoveEntriesRequest,
  AllowlistInspectResponse,
  AllowlistImportResult,
  DecisionFilters,
  AlertFilters,
  HostInfo,
  StructuredLogEntry,
  HistoryConfig,
  DecisionHistoryRecord,
  AlertHistoryRecord,
  RepeatedOffender,
  HistoryStats,
  ReapplyDecisionRequest,
  BulkReapplyDecisionsRequest,
  BulkReapplyResult,
} from './types'

// Domain API namespaces
export { healthAPI } from './health'
export { allowlistAPI } from './allowlist'
export { scenariosAPI } from './scenarios'
export { logsAPI, structuredLogsAPI } from './logs'
export { servicesAPI } from './services'
export { crowdsecAPI } from './crowdsec'
export { hostsAPI } from './hosts'
export { terminalAPI } from './terminal'
export { eventsAPI } from './events'
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
