// Re-export everything for backward compatibility
export * from './api/index'

// Preserve the default export shape for consumers using `import api from '@/lib/api'`
import { healthAPI } from './api/health'
import { allowlistAPI } from './api/allowlist'
import { scenariosAPI } from './api/scenarios'
import { logsAPI, structuredLogsAPI } from './api/logs'
import { servicesAPI } from './api/services'
import { crowdsecAPI } from './api/crowdsec'
import { hostsAPI } from './api/hosts'
import { terminalAPI } from './api/terminal'
import { eventsAPI } from './api/events'
import { hubAPI } from './api/hub'
import { simulationAPI } from './api/simulation'

export default {
  health: healthAPI,
  scenarios: scenariosAPI,
  logs: logsAPI,
  services: servicesAPI,
  crowdsec: crowdsecAPI,
  allowlist: allowlistAPI,
  hosts: hostsAPI,
  structuredLogs: structuredLogsAPI,
  terminal: terminalAPI,
  events: eventsAPI,
  hub: hubAPI,
  simulation: simulationAPI,
}
