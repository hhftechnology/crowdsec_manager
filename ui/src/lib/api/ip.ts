import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiPost } from "./client";
import type {
  PublicIPData,
  BlockedCheckResult,
  SecurityCheckResult,
} from "@/types/models";

export function usePublicIPQuery() {
  return useQuery({
    queryKey: ["ip", "public"],
    queryFn: () => apiGet<PublicIPData>("/ip/public"),
    staleTime: 60_000,
  });
}

export function useCheckBlockedMutation() {
  return useMutation({
    mutationFn: (ip: string) =>
      apiPost<BlockedCheckResult>("/ip/check-blocked", { ip }),
  });
}

export function useSecurityCheckMutation() {
  return useMutation({
    mutationFn: (ip: string) =>
      apiPost<SecurityCheckResult>("/ip/security-check", { ip }),
  });
}

export function useUnbanMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (ip: string) => apiPost<void>("/ip/unban", { ip }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["decisions"] });
    },
  });
}
