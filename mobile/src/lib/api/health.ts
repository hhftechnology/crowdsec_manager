import { ApiClient } from './client';
import type { CrowdsecHealth, DiagnosticResult, StackHealth } from './types';

export function createHealthApi(client: ApiClient) {
  return {
    async getStack() {
      return (await client.get<StackHealth>('/api/health/stack')).data;
    },
    async getCrowdsec() {
      return (await client.get<CrowdsecHealth>('/api/health/crowdsec')).data;
    },
    async getComplete() {
      return (await client.get<DiagnosticResult>('/api/health/complete')).data;
    },
  };
}
