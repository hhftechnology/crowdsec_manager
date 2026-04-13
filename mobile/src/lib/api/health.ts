import { ApiClient } from './client';
import type { CrowdsecHealth, DiagnosticResult, StackHealth } from './types';

export function createHealthApi(client: ApiClient) {
  return {
    async getStack() {
      const data = (await client.get<StackHealth>('/api/health/stack')).data;
      const containers = data?.containers ?? [];

      return {
        ...data,
        containers,
        allRunning: data?.allRunning ?? containers.every((container) => container.running),
      };
    },
    async getCrowdsec() {
      return (await client.get<CrowdsecHealth>('/api/health/crowdsec')).data;
    },
    async getComplete() {
      const data = (await client.get<DiagnosticResult>('/api/health/complete')).data;

      return {
        ...data,
        bouncers: data?.bouncers ?? [],
        decisions: data?.decisions ?? [],
      };
    },
  };
}
