import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiPut } from "./client";
import type { Profile } from "@/types/models";

export function useProfilesQuery() {
  return useQuery({
    queryKey: ["profiles"],
    queryFn: () => apiGet<Profile[]>("/profiles"),
  });
}

export function useUpdateProfilesMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (yaml: string) => apiPut<void>("/profiles", { yaml }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["profiles"] });
    },
  });
}
