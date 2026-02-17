import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiPost, apiDelete } from "./client";
import type { BackupInfo } from "@/types/models";

export function useBackupsQuery() {
  return useQuery({
    queryKey: ["backups"],
    queryFn: () => apiGet<BackupInfo[]>("/backups"),
  });
}

export function useCreateBackupMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => apiPost<BackupInfo>("/backups"),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["backups"] });
    },
  });
}

export function useRestoreBackupMutation() {
  return useMutation({
    mutationFn: (name: string) => apiPost<void>(`/backups/${name}/restore`),
  });
}

export function useDeleteBackupMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => apiDelete<void>(`/backups/${name}`),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["backups"] });
    },
  });
}

export function useCleanupBackupsMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => apiPost<void>("/backups/cleanup"),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["backups"] });
    },
  });
}
