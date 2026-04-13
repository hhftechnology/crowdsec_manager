import { ApiClient } from './client';
import type { LogStats, StructuredLogsResponse } from './types';

export function createLogsApi(client: ApiClient) {
  return {
    async crowdsec(tail = '200') {
      return (await client.get<{ logs: string }>('/api/logs/crowdsec', { params: { tail } })).data;
    },
    async traefik(tail = '200', type: 'access' | 'error' = 'access') {
      return (await client.get<{ logs: string; path?: string }>('/api/logs/traefik', { params: { tail, type } })).data;
    },
    async traefikAdvanced(tail = '1000') {
      return (await client.get<LogStats>('/api/logs/traefik/advanced', { params: { tail } })).data;
    },
    async service(service: string, tail = '200') {
      return (await client.get<{ logs: string; service: string }>(`/api/logs/${encodeURIComponent(service)}`, { params: { tail } })).data;
    },
    async structured(service: string, tail = '200', level = '') {
      return (
        await client.get<StructuredLogsResponse>(`/api/logs/structured/${encodeURIComponent(service)}`, {
          params: { tail, level: level || undefined },
        })
      ).data;
    },
    streamUrl(service: string) {
      return client.getWebSocketUrl(`/api/logs/stream/${encodeURIComponent(service)}`);
    },
  };
}
