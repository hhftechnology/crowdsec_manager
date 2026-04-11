import { ApiClient } from './client';
import type { HubCategory, HubCategoryItem, HubCategoryItemsResponse, HubOperationRecord, HubPreference } from './types';

export interface ParsedHubItems {
  items: HubCategoryItem[];
  groupedItems: Record<string, HubCategoryItem[]>;
  rawParseError: boolean;
}

function extractHubArray(record: Record<string, unknown>, ...keys: string[]): HubCategoryItem[] {
  for (const key of keys) {
    if (Array.isArray(record[key])) return record[key] as HubCategoryItem[];
  }
  return [];
}

export function parseHubJSONString(raw: string): unknown {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  try {
    return JSON.parse(trimmed);
  } catch {
    // Fallback to first parseable JSON value inside mixed CLI output.
  }

  const firstObject = trimmed.indexOf('{');
  const firstArray = trimmed.indexOf('[');

  let start = -1;
  if (firstObject >= 0 && firstArray >= 0) start = Math.min(firstObject, firstArray);
  else if (firstObject >= 0) start = firstObject;
  else if (firstArray >= 0) start = firstArray;

  if (start < 0) {
    throw new Error('No JSON payload found in hub response');
  }

  const openChar = trimmed[start];
  const closeChar = openChar === '{' ? '}' : ']';
  for (let end = trimmed.length - 1; end > start; end -= 1) {
    if (trimmed[end] !== closeChar) continue;
    const candidate = trimmed.slice(start, end + 1);
    try {
      return JSON.parse(candidate);
    } catch {
      // Keep shrinking until a valid payload is found.
    }
  }

  throw new Error('Unable to parse JSON payload from hub response');
}

export function parseHubItems(data: unknown): ParsedHubItems {
  if (!data) {
    return { items: [], groupedItems: {}, rawParseError: false };
  }

  if (Array.isArray(data)) {
    return { items: data as HubCategoryItem[], groupedItems: {}, rawParseError: false };
  }

  if (typeof data === 'string') {
    try {
      return parseHubItems(parseHubJSONString(data));
    } catch {
      return { items: [], groupedItems: {}, rawParseError: true };
    }
  }

  if (typeof data === 'object') {
    const record = data as Record<string, unknown>;
    const groupedItems: Record<string, HubCategoryItem[]> = {
      collections: extractHubArray(record, 'collections'),
      scenarios: extractHubArray(record, 'scenarios'),
      parsers: extractHubArray(record, 'parsers'),
      postoverflows: extractHubArray(record, 'postoverflows'),
      remediations: extractHubArray(record, 'remediations'),
      'appsec-configs': extractHubArray(record, 'appsec-configs', 'appsec_configs'),
      'appsec-rules': extractHubArray(record, 'appsec-rules', 'appsec_rules'),
    };

    const nonEmptyEntries = Object.entries(groupedItems).filter(([, items]) => items.length > 0);
    if (nonEmptyEntries.length > 0) {
      return {
        items: [],
        groupedItems: Object.fromEntries(nonEmptyEntries),
        rawParseError: false,
      };
    }

    const fallbackArray = Object.values(record).find((value) => Array.isArray(value));
    if (Array.isArray(fallbackArray)) {
      return { items: fallbackArray as HubCategoryItem[], groupedItems: {}, rawParseError: false };
    }
  }

  return { items: [], groupedItems: {}, rawParseError: false };
}

export function createHubApi(client: ApiClient) {
  return {
    async list() {
      return (await client.get<unknown>('/api/hub/list')).data;
    },
    async categories() {
      const payload = (await client.get<HubCategory[] | string[]>('/api/hub/categories')).data;
      if (Array.isArray(payload) && payload.length > 0 && typeof payload[0] === 'string') {
        return payload.map((key) => ({
          key: key as HubCategory['key'],
          label: key,
          cli_type: key,
          container_dir: '',
          supports_direct: true,
        }));
      }
      return payload as HubCategory[];
    },
    async items(category: string) {
      return (await client.get<HubCategoryItemsResponse>(`/api/hub/${encodeURIComponent(category)}/items`)).data;
    },
    async install(category: string, itemName: string) {
      return client.post<{ output?: string }>(`/api/hub/${encodeURIComponent(category)}/install`, {
        body: { item_name: itemName },
      });
    },
    async remove(category: string, itemName: string) {
      return client.post<{ output?: string }>(`/api/hub/${encodeURIComponent(category)}/remove`, {
        body: { item_name: itemName },
      });
    },
    async manualApply(category: string, body: { filename: string; yaml: string; target_path?: string }) {
      return client.post<{ path: string; apply_output?: string }>(`/api/hub/${encodeURIComponent(category)}/manual-apply`, {
        body,
      });
    },
    async upgradeAll() {
      return client.post<string>('/api/hub/upgrade');
    },
    async preferences() {
      const payload = (await client.get<HubPreference[] | Record<string, unknown>>('/api/hub/preferences')).data;
      if (Array.isArray(payload)) return payload;
      return [];
    },
    async preference(category: string) {
      return (await client.get<HubPreference>(`/api/hub/preferences/${encodeURIComponent(category)}`)).data;
    },
    async updatePreference(category: string, body: Partial<HubPreference>) {
      return client.put<HubPreference>(`/api/hub/preferences/${encodeURIComponent(category)}`, { body });
    },
    async history(params?: Record<string, string | number | boolean | undefined>) {
      return (await client.get<HubOperationRecord[]>('/api/hub/history', { params })).data;
    },
    async historyById(id: number) {
      return (await client.get<HubOperationRecord>(`/api/hub/history/${id}`)).data;
    },
  };
}
