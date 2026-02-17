import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiPost, apiDelete } from "./client";
import type { CaptchaStatus, CaptchaConfig } from "@/types/models";

export function useCaptchaStatusQuery() {
  return useQuery({
    queryKey: ["captcha", "status"],
    queryFn: () => apiGet<CaptchaStatus>("/captcha/status"),
  });
}

export function useSetupCaptchaMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (config: CaptchaConfig) =>
      apiPost<void>("/captcha/setup", config),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["captcha"] });
    },
  });
}

export function useDisableCaptchaMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => apiDelete<void>("/captcha"),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["captcha"] });
    },
  });
}
