import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiPut } from "./client";
import type { Settings } from "@/types/models";

export function useConfigurationQuery() {
  return useQuery({
    queryKey: ["configuration"],
    queryFn: () => apiGet<Settings>("/config"),
  });
}

export function useUpdateConfigurationMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (settings: Settings) => apiPut<void>("/config", settings),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["configuration"] });
    },
  });
}
