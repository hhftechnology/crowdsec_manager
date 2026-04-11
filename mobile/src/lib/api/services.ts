import { ApiClient } from './client';

export function createServicesApi(client: ApiClient) {
  return {
    async action(service: string, action: 'start' | 'stop' | 'restart') {
      return client.post<{ message: string }>('/api/services/action', {
        body: { service, action },
      });
    },
    async verify() {
      return (await client.get<Array<{ name: string; running: boolean; error?: string }>>('/api/services/verify')).data;
    },
  };
}
