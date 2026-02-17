import { useQuery } from "@tanstack/react-query";
import { apiGet } from "./client";
import type { Container, BouncerInfo, HealthData } from "@/types/models";

export function useContainersQuery() {
  return useQuery({
    queryKey: ["health", "containers"],
    queryFn: () => apiGet<Container[]>("/health/containers"),
    refetchInterval: 15_000,
  });
}

export function useBouncersQuery() {
  return useQuery({
    queryKey: ["health", "bouncers"],
    queryFn: () => apiGet<BouncerInfo[]>("/health/bouncers"),
    refetchInterval: 30_000,
  });
}

export function useProxyHealthQuery() {
  return useQuery({
    queryKey: ["health", "proxy"],
    queryFn: () => apiGet<HealthData>("/health"),
    refetchInterval: 30_000,
  });
}
