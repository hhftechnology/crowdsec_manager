/**
 * Barrel file that re-exports all domain API clients and types.
 * Existing imports like `import { healthAPI } from '@/lib/api'` continue to work.
 *
 * For new code, prefer importing from the specific domain client:
 *   import { healthAPI } from '@/lib/api/health'
 */

// Shared client and types
export { apiClient } from './client'
export type {
  ApiResponse,
  Container,
  HealthStatus,
  Decision,
  Bouncer,
  IPInfo,
  LogEntry,
  LogStats,
  IPCount,
  Metric,
  TraefikIntegration,
  DiagnosticResult,
  ImageTags,
} from './client'

// Domain API clients
export { healthAPI } from './health'
export { ipAPI } from './ip'
export { whitelistAPI } from './whitelist'
export { allowlistAPI } from './allowlist'
export { scenariosAPI } from './scenarios'
export { captchaAPI } from './captcha'
export { logsAPI } from './logs'
export { backupAPI } from './backup'
export { updateAPI } from './update'
export { cronAPI } from './cron'
export { servicesAPI } from './services'
export { crowdsecAPI } from './crowdsec'
export { notificationsAPI } from './notifications'
export { traefikAPI } from './traefik'
export { proxyAPI } from './proxy'
export { validationAPI } from './validation'
export { addonsAPI } from './addons'

// Domain-specific types re-exported for backward compatibility
export type { UnbanRequest } from './ip'
export type { WhitelistRequest } from './whitelist'
export type {
  Allowlist,
  AllowlistEntry,
  AllowlistCreateRequest,
  AllowlistAddEntriesRequest,
  AllowlistRemoveEntriesRequest,
  AllowlistInspectResponse,
} from './allowlist'
export type { Scenario, ScenarioSetupRequest } from './scenarios'
export type { CaptchaSetupRequest, CaptchaStatus } from './captcha'
export type { Backup, BackupRequest, RestoreRequest } from './backup'
export type { UpdateRequest, ServiceUpdateStatus } from './update'
export type { CronJobRequest } from './cron'
export type { ServiceActionRequest } from './services'
export type {
  AddDecisionRequest,
  DeleteDecisionRequest,
  EnrollRequest,
  DecisionFilters,
  AlertFilters,
} from './crowdsec'
export type { ConfigPathRequest, ConfigPathResponse } from './traefik'
export type {
  ProxyTypeInfo,
  ProxyCurrentInfo,
  ProxyFeatureInfo,
  ProxyConfigRequest,
} from './proxy'

// Default export matching the old api.ts default export shape
import { healthAPI } from './health'
import { ipAPI } from './ip'
import { whitelistAPI } from './whitelist'
import { allowlistAPI } from './allowlist'
import { scenariosAPI } from './scenarios'
import { captchaAPI } from './captcha'
import { logsAPI } from './logs'
import { backupAPI } from './backup'
import { updateAPI } from './update'
import { cronAPI } from './cron'
import { servicesAPI } from './services'
import { crowdsecAPI } from './crowdsec'
import { traefikAPI } from './traefik'
import { proxyAPI } from './proxy'
import { validationAPI } from './validation'

export default {
  health: healthAPI,
  ip: ipAPI,
  whitelist: whitelistAPI,
  scenarios: scenariosAPI,
  captcha: captchaAPI,
  logs: logsAPI,
  backup: backupAPI,
  update: updateAPI,
  cron: cronAPI,
  services: servicesAPI,
  crowdsec: crowdsecAPI,
  traefik: traefikAPI,
  allowlist: allowlistAPI,
  proxy: proxyAPI,
  validation: validationAPI,
}
