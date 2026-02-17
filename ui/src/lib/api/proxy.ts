import { useQuery } from "@tanstack/react-query";
import { apiGet } from "./client";
import type { ProxyInfo } from "@/types/proxy";

export function useProxyInfoQuery() {
  return useQuery({
    queryKey: ["proxy", "info"],
    queryFn: () => apiGet<ProxyInfo>("/proxy/info"),
    staleTime: 120_000,
  });
}
