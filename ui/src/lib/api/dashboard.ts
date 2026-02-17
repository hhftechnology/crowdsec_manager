import { useQuery } from "@tanstack/react-query";
import { apiGet } from "./client";
import type { DashboardData } from "@/types/models";

export function useDashboardQuery() {
  return useQuery({
    queryKey: ["dashboard"],
    queryFn: () => apiGet<DashboardData>("/dashboard"),
    refetchInterval: 30_000,
  });
}
