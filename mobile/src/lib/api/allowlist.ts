import { ApiClient } from './client';
import type { Allowlist, AllowlistInspectResponse } from './types';

export function createAllowlistApi(client: ApiClient) {
  return {
    async list() {
      const payload = (await client.get<{ allowlists: Allowlist[]; count: number } | Allowlist[]>('/api/allowlist/list'))
        .data;
      if (Array.isArray(payload)) {
        return { allowlists: payload, count: payload.length };
      }
      return payload;
    },
    async create(input: { name: string; description: string }) {
      return client.post<Allowlist>('/api/allowlist/create', { body: input });
    },
    async inspect(name: string) {
      return (await client.get<AllowlistInspectResponse>(`/api/allowlist/inspect/${encodeURIComponent(name)}`)).data;
    },
    async addEntries(input: { allowlist_name: string; values: string[]; expiration?: string; description?: string }) {
      return client.post<null>('/api/allowlist/add', { body: input });
    },
    async removeEntries(input: { allowlist_name: string; values: string[] }) {
      return client.post<null>('/api/allowlist/remove', { body: input });
    },
    async delete(name: string) {
      return client.delete<null>(`/api/allowlist/${encodeURIComponent(name)}`);
    },
  };
}
