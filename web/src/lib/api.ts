// Re-export everything for backward compatibility
export * from './api/index'

// Preserve the default export shape for consumers using `import api from '@/lib/api'`
import { healthAPI } from './api/health'
import { ipAPI } from './api/ip'
import { whitelistAPI } from './api/whitelist'
import { allowlistAPI } from './api/allowlist'
import { scenariosAPI } from './api/scenarios'
import { captchaAPI } from './api/captcha'
import { logsAPI, structuredLogsAPI } from './api/logs'
import { backupAPI } from './api/backup'
import { cronAPI } from './api/cron'
import { servicesAPI } from './api/services'
import { crowdsecAPI } from './api/crowdsec'
import { traefikAPI } from './api/traefik'
import { updateAPI } from './api/update'
import { hostsAPI } from './api/hosts'
import { terminalAPI } from './api/terminal'
import { eventsAPI } from './api/events'
import { configValidationAPI } from './api/config-validation'
import { profilesAPI } from './api/profiles'
import { hubAPI } from './api/hub'
import { simulationAPI } from './api/simulation'

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
  hosts: hostsAPI,
  structuredLogs: structuredLogsAPI,
  terminal: terminalAPI,
  events: eventsAPI,
  configValidation: configValidationAPI,
  profiles: profilesAPI,
  hub: hubAPI,
  simulation: simulationAPI,
}
