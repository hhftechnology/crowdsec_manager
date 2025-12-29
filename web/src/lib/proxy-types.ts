// Proxy Types and Interfaces for Multi-Proxy Architecture

export type ProxyType = 'traefik' | 'nginx' | 'caddy' | 'haproxy' | 'zoraxy' | 'standalone'

export type Feature = 'whitelist' | 'captcha' | 'logs' | 'bouncer' | 'health' | 'appsec' | 'backup' | 'cron' | 'pangolin' | 'gerbil'

export interface ProxyInfo {
  type: ProxyType
  name: string
  description: string
  icon: string
  features: Feature[]
  experimental?: boolean
  running?: boolean
  connected?: boolean
}

export interface ProxyStatus {
  type: ProxyType
  running: boolean
  connected: boolean
  containerName: string
  healthStatus: 'healthy' | 'unhealthy' | 'unknown'
}

export interface HealthCheckItem {
  status: 'healthy' | 'unhealthy' | 'degraded' | 'warning' | 'info'
  message: string
  error?: string
  details?: string
  metrics?: Record<string, any>
}

export interface HealthStatus {
  containers: Container[]
  allRunning: boolean
  timestamp: string
}

export interface Container {
  name: string
  id: string
  status: string
  running: boolean
}

export interface ProxyHealthData {
  checks: HealthCheckItem[]
  overall: 'healthy' | 'unhealthy' | 'degraded' | 'warning' | 'info'
  timestamp: string
}

export interface ComprehensiveHealthData {
  proxyType: ProxyType
  crowdsecHealth: HealthCheckItem
  proxyHealth: HealthCheckItem
  bouncerHealth: HealthCheckItem
  containers: Container[]
  timestamp: Date
  overallStatus: 'healthy' | 'unhealthy' | 'degraded' | 'warning' | 'info'
}

export interface NavigationItem {
  name: string
  href: string
  icon: any // Lucide icon component
  available: boolean
  tooltip?: string
}

export interface NavigationGroup {
  title: string
  items: NavigationItem[]
}

export interface FeatureAvailability {
  [key: string]: boolean
}

// Proxy configuration constants
export const PROXY_TYPES: ProxyInfo[] = [
  {
    type: 'traefik',
    name: 'Traefik',
    description: 'Modern reverse proxy with dynamic configuration',
    icon: 'Network',
    features: ['whitelist', 'captcha', 'logs', 'bouncer', 'health', 'appsec']
  },
  {
    type: 'nginx',
    name: 'Nginx Proxy Manager',
    description: 'Web-based nginx proxy manager',
    icon: 'Server',
    features: ['logs', 'bouncer', 'health']
  },
  {
    type: 'caddy',
    name: 'Caddy',
    description: 'Automatic HTTPS web server',
    icon: 'Shield',
    features: ['bouncer', 'health']
  },
  {
    type: 'haproxy',
    name: 'HAProxy',
    description: 'High-performance load balancer',
    icon: 'Activity',
    features: ['bouncer', 'health']
  },
  {
    type: 'zoraxy',
    name: 'Zoraxy',
    description: 'Lightweight reverse proxy (experimental)',
    icon: 'Zap',
    features: ['health'],
    experimental: true
  },
  {
    type: 'standalone',
    name: 'Standalone',
    description: 'CrowdSec only, no reverse proxy',
    icon: 'Database',
    features: ['health']
  }
]

export const FEATURE_DESCRIPTIONS: Record<Feature, string> = {
  whitelist: 'Manage IP whitelists at the proxy level',
  captcha: 'Configure captcha middleware protection',
  logs: 'Parse and analyze proxy access logs',
  bouncer: 'CrowdSec bouncer integration and monitoring',
  health: 'Health monitoring and diagnostics',
  appsec: 'Application security and WAF features',
  backup: 'System configuration backup and management',
  cron: 'Scheduled task management',
  pangolin: 'Pangolin interface integration',
  gerbil: 'Gerbil interface integration'
}