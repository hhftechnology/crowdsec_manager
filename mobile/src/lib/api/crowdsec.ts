import { ApiClient } from './client';
import type {
  AddDecisionRequest,
  AlertsResponse,
  Bouncer,
  CrowdsecAlert,
  Decision,
  DecisionHistoryResponse,
  DeleteDecisionRequest,
  DecisionsResponse,
  HistoryActivityResponse,
  MetricsResponse,
  ReapplyDecisionRequest,
} from './types';

export function createCrowdsecApi(client: ApiClient) {
  return {
    async decisions(params?: Record<string, string | number | boolean | undefined>) {
      const payload = (await client.get<DecisionsResponse | Decision[]>('/api/crowdsec/decisions', { params })).data;
      if (Array.isArray(payload)) {
        return { decisions: payload, count: payload.length };
      }
      return {
        decisions: payload.decisions || [],
        count: payload.count ?? payload.decisions?.length ?? 0,
        total: payload.total ?? payload.count ?? payload.decisions?.length ?? 0,
        limit: payload.limit,
        offset: payload.offset,
      };
    },
    async decisionsAnalysis(params?: Record<string, string | number | boolean | undefined>) {
      const payload = (
        await client.get<DecisionsResponse | Record<string, unknown>>('/api/crowdsec/decisions/analysis', { params })
      ).data;
      if (typeof payload === 'object' && payload && 'decisions' in payload) {
        const typedPayload = payload as DecisionsResponse;
        return {
          decisions: typedPayload.decisions || [],
          count: typedPayload.count ?? typedPayload.decisions?.length ?? 0,
          total: typedPayload.total ?? typedPayload.count ?? typedPayload.decisions?.length ?? 0,
          limit: typedPayload.limit,
          offset: typedPayload.offset,
        };
      }
      return payload;
    },
    async addDecision(body: AddDecisionRequest) {
      return client.post<{ output?: string }>('/api/crowdsec/decisions', { body });
    },
    async deleteDecision(params: DeleteDecisionRequest) {
      return client.delete<{ output?: string }>('/api/crowdsec/decisions', { params });
    },
    async importDecisions(file: File) {
      const formData = new FormData();
      formData.append('file', file);
      return client.post<{ output?: string }>('/api/crowdsec/decisions/import', { body: formData });
    },
    async alertsAnalysis(params?: Record<string, string | number | boolean | undefined>) {
      const payload = (
        await client.get<AlertsResponse | Record<string, unknown>>('/api/crowdsec/alerts/analysis', { params })
      ).data;
      if (typeof payload === 'object' && payload && 'alerts' in payload) {
        return payload as AlertsResponse;
      }
      return payload;
    },
    async inspectAlert(id: number) {
      return (await client.get<CrowdsecAlert>(`/api/crowdsec/alerts/${id}`)).data;
    },
    async deleteAlert(id: number) {
      return client.delete<null>(`/api/crowdsec/alerts/${id}`);
    },
    async metrics() {
      return (await client.get<MetricsResponse>('/api/crowdsec/metrics')).data;
    },
    async bouncers() {
      return (await client.get<{ bouncers: Bouncer[]; count: number }>('/api/crowdsec/bouncers')).data;
    },
    async decisionHistory(params?: Record<string, string | number | boolean | undefined>) {
      const payload = (
        await client.get<DecisionHistoryResponse | { decisions?: unknown[]; count?: number; total?: number }>(
          '/api/crowdsec/decisions/history',
          { params },
        )
      ).data;

      return {
        decisions: payload.decisions || [],
        count: payload.count ?? payload.decisions?.length ?? 0,
        total: payload.total ?? payload.count ?? payload.decisions?.length ?? 0,
      };
    },
    async reapplyDecision(body: ReapplyDecisionRequest) {
      return client.post<{ message?: string }>('/api/crowdsec/decisions/history/reapply', { body });
    },
    async decisionsSummary() {
      const payload = (await client.get<DecisionsResponse | Decision[]>('/api/crowdsec/decisions', { params: { summary: 'true' } })).data;
      if (Array.isArray(payload)) return { count: payload.length };
      return { count: payload.count ?? (payload.decisions?.length ?? 0) };
    },
    async historyActivity(params: { window: '24h' | '7d'; bucket: 'hour' | 'day' }) {
      return (await client.get<HistoryActivityResponse>('/api/crowdsec/history/activity', { params })).data;
    },
    toDecisionRows(input: DecisionsResponse | Decision[] | null | undefined): Decision[] {
      if (!input) return [];
      return Array.isArray(input) ? input : input.decisions || [];
    },
  };
}
