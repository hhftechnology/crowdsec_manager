import { ApiClient } from './client';

export function createTerminalApi(client: ApiClient) {
  return {
    getWebSocketUrl(container: string) {
      return client.getWebSocketUrl(`/api/terminal/${encodeURIComponent(container)}`);
    },
  };
}
