export type ProxyType =
  | "traefik"
  | "nginx"
  | "caddy"
  | "haproxy"
  | "zoraxy"
  | "standalone";

export type Feature =
  | "whitelist"
  | "captcha"
  | "logs"
  | "bouncer"
  | "health";

export interface ProxyInfo {
  type: ProxyType;
  name: string;
  features: Feature[];
  containerName: string;
}
