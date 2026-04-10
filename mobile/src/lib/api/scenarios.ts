import { ApiClient } from './client';
import type { ScenarioFile, ScenarioItem, ScenarioListResponse, ScenarioSetupPayload } from './types';

export function createScenariosApi(client: ApiClient) {
  return {
    async list() {
      const payload = (await client.get<ScenarioListResponse | ScenarioItem[]>('/api/scenarios/list')).data;
      if (Array.isArray(payload)) {
        return { scenarios: payload, count: payload.length };
      }
      return payload;
    },
    async setup(payload: ScenarioSetupPayload) {
      return client.post<Array<Record<string, unknown>>>('/api/scenarios/setup', { body: payload });
    },
    async files() {
      return (await client.get<ScenarioFile[]>('/api/scenarios/files')).data;
    },
    async deleteFile(filename: string) {
      return client.delete<null>('/api/scenarios/file', { body: { filename } });
    },
  };
}
