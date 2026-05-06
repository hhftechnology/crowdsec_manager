import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useApi } from '@/contexts/ApiContext';
import { invalidateDecisionsAndAlerts } from '@/lib/queryInvalidation';
import type { AddDecisionRequest, DeleteDecisionRequest, ReapplyDecisionRequest } from '@/lib/api';

export type SecurityFilters = Record<string, string | number | boolean | undefined>;

const SECURITY_REFETCH_MS = 30_000;

export function useDecisionsQuery(filters: SecurityFilters) {
  const { api } = useApi();
  return useQuery({
    queryKey: ['decisions-analysis', filters],
    queryFn: () => api!.crowdsec.decisionsAnalysis(filters),
    enabled: Boolean(api),
    refetchInterval: SECURITY_REFETCH_MS,
  });
}

export function useAlertsQuery(filters: SecurityFilters = {}) {
  const { api } = useApi();
  return useQuery({
    queryKey: ['alerts-analysis', filters],
    queryFn: () => api!.crowdsec.alertsAnalysis(filters),
    enabled: Boolean(api),
    refetchInterval: SECURITY_REFETCH_MS,
  });
}

export function useDecisionHistoryQuery(page: number, pageSize: number) {
  const { api } = useApi();
  return useQuery({
    queryKey: ['decision-history', { page, pageSize }],
    queryFn: () => api!.crowdsec.decisionHistory({
      limit: pageSize,
      offset: (page - 1) * pageSize,
    }),
    enabled: Boolean(api),
  });
}

export function useMetricsQuery() {
  const { api } = useApi();
  return useQuery({
    queryKey: ['crowdsec-metrics'],
    queryFn: () => api!.crowdsec.metrics(),
    enabled: Boolean(api),
  });
}

export function useDecisionMutations() {
  const { api } = useApi();
  const queryClient = useQueryClient();

  const invalidate = async () => {
    await invalidateDecisionsAndAlerts(queryClient);
  };

  return {
    addDecision: useMutation({
      mutationFn: (body: AddDecisionRequest) => api!.crowdsec.addDecision(body),
      onSuccess: invalidate,
    }),
    deleteDecision: useMutation({
      mutationFn: (params: DeleteDecisionRequest) => api!.crowdsec.deleteDecision(params),
      onSuccess: invalidate,
    }),
    bulkDeleteDecisions: useMutation({
      mutationFn: (ids: number[]) => api!.crowdsec.bulkDeleteDecisions(ids),
      onSuccess: invalidate,
    }),
    reapplyDecision: useMutation({
      mutationFn: (body: ReapplyDecisionRequest) => api!.crowdsec.reapplyDecision(body),
      onSuccess: invalidate,
    }),
    importDecisions: useMutation({
      mutationFn: (file: File) => api!.crowdsec.importDecisions(file),
      onSuccess: invalidate,
    }),
    deleteAlert: useMutation({
      mutationFn: (id: number) => api!.crowdsec.deleteAlert(id),
      onSuccess: invalidate,
    }),
  };
}
