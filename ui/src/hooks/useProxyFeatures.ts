import { useEffect } from "react";
import { useProxyInfoQuery } from "@/lib/api/proxy";
import { useProxyStore } from "@/store/proxy";

export function useProxyFeatures() {
  const { data } = useProxyInfoQuery();
  const { setProxyInfo, proxyType, features, hasFeature } = useProxyStore();

  useEffect(() => {
    if (data) {
      setProxyInfo(data.type, data.features, data.containerName);
    }
  }, [data, setProxyInfo]);

  return { proxyType, features, hasFeature, isLoaded: !!data };
}
