import { useQuery } from "@tanstack/react-query";
import { apiGet } from "./client";
import type { LogEntry } from "@/types/models";

export interface LogParams {
  service?: string;
  lines?: number;
}

function buildQueryString(params: LogParams): string {
  const search = new URLSearchParams();
  if (params.service) search.set("service", params.service);
  if (params.lines) search.set("lines", String(params.lines));
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

export function useLogsQuery(params: LogParams = {}) {
  return useQuery({
    queryKey: ["logs", params],
    queryFn: () => apiGet<LogEntry[]>(`/logs${buildQueryString(params)}`),
    enabled: !!params.service,
  });
}
