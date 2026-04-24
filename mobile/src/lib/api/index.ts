import type { ConnectionProfile } from '@/lib/connection';
import { ApiClient } from './client';
import { createAllowlistApi } from './allowlist';
import { createCrowdsecApi } from './crowdsec';
import { createHealthApi } from './health';
import { createHubApi } from './hub';
import { createLogsApi } from './logs';
import { createScenariosApi } from './scenarios';
import { createServicesApi } from './services';
import { createTerminalApi } from './terminal';

export function createApi(profile: ConnectionProfile) {
  const client = new ApiClient(profile);

  return {
    client,
    health: createHealthApi(client),
    allowlist: createAllowlistApi(client),
    scenarios: createScenariosApi(client),
    logs: createLogsApi(client),
    crowdsec: createCrowdsecApi(client),
    hub: createHubApi(client),
    services: createServicesApi(client),
    terminal: createTerminalApi(client),
  };
}

export type ApiService = ReturnType<typeof createApi>;
export { ApiClient, ApiError } from './client';
export * from './types';
