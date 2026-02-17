import type { ProxyInfo } from "./proxy";

export interface Container {
  id: string;
  name: string;
  image: string;
  state: "running" | "stopped" | "restarting";
  status: string;
  health: "healthy" | "unhealthy" | "none";
}

export interface DashboardData {
  containers: Container[];
  activeDecisions: number;
  activeBouncers: number;
  containerCount: string;
}

export interface Decision {
  id: number;
  origin: string;
  type: string;
  scope: string;
  value: string;
  scenario: string;
  duration: string;
  until: string;
}

export interface Alert {
  id: number;
  scenario: string;
  source_ip: string;
  source_scope: string;
  source_value: string;
  created_at: string;
  events_count: number;
}

export interface WhitelistEntry {
  ip: string;
  source: string;
  added_at: string;
  reason?: string;
}

export interface AllowlistEntry {
  ip: string;
  created_at: string;
  reason?: string;
}

export interface Scenario {
  name: string;
  status: string;
  version: string;
  path: string;
}

export interface CaptchaConfig {
  provider: string;
  site_key: string;
  secret_key: string;
  enabled: boolean;
}

export interface CaptchaStatus {
  enabled: boolean;
  provider?: string;
  site_key?: string;
  html_exists: boolean;
  config_ok: boolean;
}

export interface NotificationConfig {
  webhook_url: string;
  geoapify_key?: string;
  cti_key?: string;
  enabled: boolean;
  mode: "simple" | "advanced";
  advanced_yaml?: string;
}

export interface NotificationStatus {
  configured: boolean;
  source?: string;
  webhook_url?: string;
}

export interface BackupInfo {
  name: string;
  created_at: string;
  size: number;
}

export interface BouncerInfo {
  name: string;
  ip_address: string;
  type: string;
  last_pull: string;
  valid: boolean;
}

export interface HealthData {
  containers: Container[];
  bouncers: BouncerInfo[];
  proxy: ProxyInfo;
}

export interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  source?: string;
}

export interface Settings {
  [key: string]: string;
}

export interface Profile {
  name: string;
  filters: string[];
  decisions: { type: string; duration: string }[];
  notifications: string[];
  on_success: string;
}

export interface ServiceInfo {
  name: string;
  container_id: string;
  state: "running" | "stopped" | "restarting";
  status: string;
  image: string;
}

export interface PublicIPData {
  ip: string;
}

export interface BlockedCheckResult {
  ip: string;
  blocked: boolean;
  reason?: string;
}

export interface SecurityCheckResult {
  ip: string;
  reputation: string;
  country?: string;
  reports: number;
}
