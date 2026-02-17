import {
  useQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { apiGet, apiPost, apiDelete } from "./client";
import type { AllowlistEntry } from "@/types/models";

export function useAllowlistQuery() {
  return useQuery({
    queryKey: ["allowlist"],
    queryFn: () => apiGet<AllowlistEntry[]>("/allowlist"),
  });
}

export function useAddAllowlistMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { ip: string; reason?: string }) =>
      apiPost<void>("/allowlist", data),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["allowlist"] });
    },
  });
}

export function useRemoveAllowlistMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (ip: string) => apiDelete<void>(`/allowlist/${ip}`),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["allowlist"] });
    },
  });
}
