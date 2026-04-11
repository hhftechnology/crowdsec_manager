import { ApiClient } from './client';
import type { IPBlockedStatus, IPSecurity, PublicIP } from './types';

export function createIPApi(client: ApiClient) {
  return {
    async getPublicIP() {
      return (await client.get<PublicIP>('/api/ip/public')).data;
    },
    async checkBlocked(ip: string) {
      return (await client.get<IPBlockedStatus>(`/api/ip/blocked/${encodeURIComponent(ip)}`)).data;
    },
    async checkSecurity(ip: string) {
      return (await client.get<IPSecurity>(`/api/ip/security/${encodeURIComponent(ip)}`)).data;
    },
    async unban(ip: string) {
      return client.post<{ output?: string }>('/api/ip/unban', { body: { ip } });
    },
  };
}
