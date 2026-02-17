import { useQuery } from "@tanstack/react-query";
import { apiGet } from "./client";
import type { Decision } from "@/types/models";

export interface DecisionFilters {
  ip?: string;
  scope?: string;
  type?: string;
  origin?: string;
}

function buildQueryString(filters: DecisionFilters): string {
  const params = new URLSearchParams();
  if (filters.ip) params.set("ip", filters.ip);
  if (filters.scope) params.set("scope", filters.scope);
  if (filters.type) params.set("type", filters.type);
  if (filters.origin) params.set("origin", filters.origin);
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

export function useDecisionsQuery(filters: DecisionFilters = {}) {
  return useQuery({
    queryKey: ["decisions", filters],
    queryFn: () =>
      apiGet<Decision[]>(`/decisions${buildQueryString(filters)}`),
    refetchInterval: 30_000,
  });
}
