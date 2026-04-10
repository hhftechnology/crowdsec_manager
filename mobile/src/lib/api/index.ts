import { ApiClient } from './client';
import { createAllowlistApi } from './allowlist';
import { createCrowdsecApi } from './crowdsec';
import { createHealthApi } from './health';
import { createHubApi } from './hub';
import { createIPApi } from './ip';
import { createLogsApi } from './logs';
import { createScenariosApi } from './scenarios';
import { createServicesApi } from './services';
import { createTerminalApi } from './terminal';

export function createApi(baseUrl: string) {
  const client = new ApiClient(baseUrl);

  return {
    client,
    health: createHealthApi(client),
    ip: createIPApi(client),
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
