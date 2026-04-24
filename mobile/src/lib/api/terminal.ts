import type { WebSocketUrlOptions } from './client';
import { ApiClient } from './client';

export function createTerminalApi(client: ApiClient) {
  return {
    getWebSocketUrl(container: string, options?: WebSocketUrlOptions) {
      return client.getWebSocketUrl('/api/terminal/' + encodeURIComponent(container), undefined, options);
    },
  };
}
