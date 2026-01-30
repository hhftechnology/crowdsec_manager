export interface ContainerInfo {
  name: string
  id: string
  status: ContainerStatus
  running: boolean
  capabilities: string[]
  role: ContainerRole
  image?: string
  healthStatus?: HealthStatus
}

export enum ContainerStatus {
  RUNNING = 'running',
  STOPPED = 'stopped',
  RESTARTING = 'restarting',
  UNKNOWN = 'unknown'
}

export enum ContainerRole {
  PROXY = 'proxy',
  SECURITY = 'security',
  ADDON = 'addon',
  MONITORING = 'monitoring'
}

export enum HealthStatus {
  HEALTHY = 'healthy',
  UNHEALTHY = 'unhealthy',
  DEGRADED = 'degraded',
  UNKNOWN = 'unknown'
}

export interface FeatureAvailability {
  captcha: boolean
  backup: boolean
  cronJobs: boolean
  whitelistProxy: boolean
  logs: boolean
  pangolin: boolean
  gerbil: boolean
  appsec: boolean
  bouncer: boolean
  addons: boolean
}

export interface EnvironmentFlags {
  backupEnabled: boolean
  cronEnabled: boolean
  pangolinEnabled: boolean
  gerbilEnabled: boolean
  proxyType: string
  customFlags: Record<string, boolean>
}

export interface DeploymentConfiguration {
  proxyType: string | null
  containers: ContainerInfo[]
  features: FeatureAvailability
  environment: EnvironmentFlags
  detectedAt: Date
  confidence: number // 0-1 confidence in detection accuracy
}
