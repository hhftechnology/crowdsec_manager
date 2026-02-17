import { usePublicIPQuery } from "@/lib/api/ip";

export function usePublicIP() {
  const { data, isLoading, error } = usePublicIPQuery();
  return {
    ip: data?.ip ?? null,
    isLoading,
    error,
  };
}
