import { useQuery } from "@tanstack/react-query";
import { apiGet } from "./client";
import type { Alert } from "@/types/models";

export interface AlertFilters {
  scenario?: string;
  ip?: string;
  since?: string;
  limit?: number;
}

function buildQueryString(filters: AlertFilters): string {
  const params = new URLSearchParams();
  if (filters.scenario) params.set("scenario", filters.scenario);
  if (filters.ip) params.set("ip", filters.ip);
  if (filters.since) params.set("since", filters.since);
  if (filters.limit) params.set("limit", String(filters.limit));
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

export function useAlertsQuery(filters: AlertFilters = {}) {
  return useQuery({
    queryKey: ["alerts", filters],
    queryFn: () => apiGet<Alert[]>(`/alerts${buildQueryString(filters)}`),
    refetchInterval: 30_000,
  });
}
