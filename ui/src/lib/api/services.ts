import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiPost } from "./client";
import type { ServiceInfo } from "@/types/models";

export function useServicesQuery() {
  return useQuery({
    queryKey: ["services"],
    queryFn: () => apiGet<ServiceInfo[]>("/services"),
    refetchInterval: 15_000,
  });
}

export function useStartServiceMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => apiPost<void>(`/services/${name}/start`),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["services"] });
      await queryClient.invalidateQueries({
        queryKey: ["health", "containers"],
      });
    },
  });
}

export function useStopServiceMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => apiPost<void>(`/services/${name}/stop`),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["services"] });
      await queryClient.invalidateQueries({
        queryKey: ["health", "containers"],
      });
    },
  });
}

export function useRestartServiceMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => apiPost<void>(`/services/${name}/restart`),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["services"] });
      await queryClient.invalidateQueries({
        queryKey: ["health", "containers"],
      });
    },
  });
}
