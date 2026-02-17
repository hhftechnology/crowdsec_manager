import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiPost } from "./client";
import type { NotificationStatus, NotificationConfig } from "@/types/models";

export function useNotificationStatusQuery() {
  return useQuery({
    queryKey: ["notifications", "status"],
    queryFn: () => apiGet<NotificationStatus>("/notifications/status"),
  });
}

export function useSaveNotificationMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (config: NotificationConfig) =>
      apiPost<void>("/notifications", config),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
  });
}

export function useTestNotificationMutation() {
  return useMutation({
    mutationFn: () => apiPost<void>("/notifications/test"),
  });
}
