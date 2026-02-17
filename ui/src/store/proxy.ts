import { create } from "zustand";
import { devtools } from "zustand/middleware";
import type { ProxyType, Feature } from "@/types/proxy";

interface ProxyState {
  proxyType: ProxyType | null;
  features: Feature[];
  containerName: string;
  setProxyInfo: (
    type: ProxyType,
    features: Feature[],
    container: string,
  ) => void;
  hasFeature: (feature: Feature) => boolean;
}

export const useProxyStore = create<ProxyState>()(
  devtools((set, get) => ({
    proxyType: null,
    features: [],
    containerName: "",
    setProxyInfo: (type, features, container) =>
      set({ proxyType: type, features, containerName: container }),
    hasFeature: (feature) => get().features.includes(feature),
  })),
);
