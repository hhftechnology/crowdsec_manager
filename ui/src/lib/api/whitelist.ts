import {
  useQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { apiGet, apiPost, apiDelete } from "./client";
import type { WhitelistEntry } from "@/types/models";

export function useWhitelistQuery() {
  return useQuery({
    queryKey: ["whitelist"],
    queryFn: () => apiGet<WhitelistEntry[]>("/whitelist"),
  });
}

export function useAddWhitelistMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { ip: string; reason?: string }) =>
      apiPost<void>("/whitelist", data),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["whitelist"] });
    },
  });
}

export function useQuickWhitelistMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => apiPost<void>("/whitelist/quick"),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["whitelist"] });
    },
  });
}

export function useRemoveWhitelistMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (ip: string) => apiDelete<void>(`/whitelist/${ip}`),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["whitelist"] });
    },
  });
}
