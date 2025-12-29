import { describe, it, expect, vi } from 'vitest'
import * as fc from 'fast-check'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import Whitelist from '@/pages/Whitelist'
import { 
  ContainerInfo, ContainerStatus, ContainerRole, HealthStatus,
  FeatureAvailability, EnvironmentFlags, DeploymentConfiguration 
} from '@/lib/deployment-types'
import React from 'react'

// Mock the API module
vi.mock('@/lib/api', () => ({
  default: {
    whitelist: {
      view: vi.fn().mockResolvedValue({ data: { data: { crowdsec: [], traefik: [] } } }),
      whitelistCurrent: vi.fn().mockResolvedValue({ data: { success: true } }),
      whitelistManual: vi.fn().mockResolvedValue({ data: { success: true } }),
      whitelistCIDR: vi.fn().mockResolvedValue({ data: { success: true } }),
      setupComprehensive: vi.fn().mockResolvedValue({ data: { success: true } })
    },
    ip: {
      getPublicIP: vi.fn().mockResolvedValue({ data: { data: { ip: '203.0.113.1' } } })
    },
    health: {
      checkStack: vi.fn().mockResolvedValue({ 
        data: { 
          success: true, 
          data: { containers: [] } 
        } 
      })
    },
    proxy: {
      getCurrent: vi.fn().mockResolvedValue({ 
        data: { 
          success: true, 
          data: { type: 'standalone' } 
        } 
      })
    }
  }
}))

// Mock deployment context hooks with simple implementation
let mockDeployment: DeploymentConfiguration | null = null

vi.mock('@/contexts/DeploymentContext', () => ({
  useDeployment: () => ({
    deployment: mockDeployment,
    isLoading: false,
    error: null,
    refreshDeployment: vi.fn()
  }),
  useContainers: () => mockDeployment?.containers || [],
  useRunningContainers: () => mockDeployment?.containers.filter(c => c.running) || [],
  useFeatures: () => mockDeployment?.features || {
    captcha: false,
    backup: false,
    cronJobs: false,
    whitelistProxy: false,
    logs: false,
    pangolin: false,
    gerbil: false,
    appsec: false,
    bouncer: false
  },
  useFeature: (feature: keyof FeatureAvailability) => mockDeployment?.features[feature] || false,
  useProxyType: () => mockDeployment?.proxyType || null,
  useEnvironmentFlags: () => mockDeployment?.environment || {
    backupEnabled: false,
    cronEnabled: false,
    pangolinEnabled: false,
    gerbilEnabled: false,
    proxyType: 'standalone',
    customFlags: {}
  },
  DeploymentProvider: ({ children }: { children: React.ReactNode }) => children
}))

// Generators for test data
const containerGenerator = fc.record({
  name: fc.oneof(
    fc.constant('crowdsec'),
    fc.constant('traefik'),
    fc.constant('nginx'),
    fc.constant('caddy'),
    fc.constant('haproxy'),
    fc.constant('zoraxy'),
    fc.constant('pangolin'),
    fc.constant('gerbil'),
    fc.string({ minLength: 1, maxLength: 20 })
  ),
  id: fc.string({ minLength: 8, maxLength: 64 }),
  status: fc.constantFrom(
    ContainerStatus.RUNNING,
    ContainerStatus.STOPPED,
    ContainerStatus.RESTARTING,
    ContainerStatus.UNKNOWN
  ),
  running: fc.boolean(),
  role: fc.constantFrom(
    ContainerRole.PROXY,
    ContainerRole.SECURITY,
    ContainerRole.ADDON,
    ContainerRole.MONITORING
  ),
  healthStatus: fc.constantFrom(
    HealthStatus.HEALTHY,
    HealthStatus.UNHEALTHY,
    HealthStatus.UNKNOWN
  ),
  capabilities: fc.array(fc.string({ minLength: 1, maxLength: 10 }), { minLength: 0, maxLength: 5 })
}).map((container): ContainerInfo => ({
  ...container,
  // Ensure consistency between running and status
  status: container.running ? ContainerStatus.RUNNING : ContainerStatus.STOPPED,
  healthStatus: container.running ? HealthStatus.HEALTHY : HealthStatus.UNHEALTHY,
  // Ensure role matches container name
  role: determineRoleFromName(container.name),
  // Ensure capabilities match container type and running state
  capabilities: determineCapabilitiesFromName(container.name, container.running)
}))

function determineRoleFromName(name: string): ContainerRole {
  const lowerName = name.toLowerCase()
  if (lowerName.includes('traefik') || lowerName.includes('nginx') || 
      lowerName.includes('caddy') || lowerName.includes('haproxy') || 
      lowerName.includes('zoraxy')) {
    return ContainerRole.PROXY
  }
  if (lowerName.includes('crowdsec')) {
    return ContainerRole.SECURITY
  }
  if (lowerName.includes('pangolin') || lowerName.includes('gerbil')) {
    return ContainerRole.ADDON
  }
  return ContainerRole.MONITORING
}

function determineCapabilitiesFromName(name: string, running: boolean): string[] {
  if (!running) return []
  
  const lowerName = name.toLowerCase()
  const capabilities: string[] = ['health']
  
  if (lowerName.includes('traefik')) {
    capabilities.push('whitelist', 'captcha', 'logs', 'bouncer', 'appsec')
  } else if (lowerName.includes('nginx') || lowerName.includes('caddy') || 
             lowerName.includes('haproxy') || lowerName.includes('zoraxy')) {
    capabilities.push('whitelist', 'logs', 'bouncer')
  } else if (lowerName.includes('crowdsec')) {
    capabilities.push('bouncer', 'logs')
  } else if (lowerName.includes('pangolin') || lowerName.includes('gerbil')) {
    capabilities.push('logs')
  }
  
  return capabilities
}

const deploymentGenerator = fc.record({
  containers: fc.array(containerGenerator, { minLength: 0, maxLength: 8 }),
  proxyType: fc.oneof(
    fc.constant('traefik'),
    fc.constant('nginx'),
    fc.constant('caddy'),
    fc.constant('haproxy'),
    fc.constant('zoraxy'),
    fc.constant('standalone'),
    fc.constant(null)
  ),
  confidence: fc.float({ min: 0, max: 1 })
}).map((config): DeploymentConfiguration => {
  const runningContainers = config.containers.filter(c => c.running)
  const runningProxies = runningContainers.filter(c => c.role === ContainerRole.PROXY)
  
  // Determine features based on running containers
  const features: FeatureAvailability = {
    captcha: runningContainers.some(c => c.capabilities.includes('captcha')),
    backup: true, // Assume always available
    cronJobs: true, // Assume always available
    whitelistProxy: runningContainers.some(c => c.capabilities.includes('whitelist')),
    logs: runningContainers.some(c => c.capabilities.includes('logs')),
    pangolin: runningContainers.some(c => c.name.includes('pangolin')),
    gerbil: runningContainers.some(c => c.name.includes('gerbil')),
    appsec: runningContainers.some(c => c.capabilities.includes('appsec')),
    bouncer: runningContainers.some(c => c.capabilities.includes('bouncer'))
  }
  
  // Determine proxy type from running containers if not set
  let actualProxyType = config.proxyType
  if (!actualProxyType && runningProxies.length > 0) {
    const proxyName = runningProxies[0].name.toLowerCase()
    if (proxyName.includes('traefik')) actualProxyType = 'traefik'
    else if (proxyName.includes('nginx')) actualProxyType = 'nginx'
    else if (proxyName.includes('caddy')) actualProxyType = 'caddy'
    else if (proxyName.includes('haproxy')) actualProxyType = 'haproxy'
    else if (proxyName.includes('zoraxy')) actualProxyType = 'zoraxy'
    else actualProxyType = 'standalone'
  } else if (!actualProxyType) {
    actualProxyType = 'standalone'
  }
  
  const environment: EnvironmentFlags = {
    backupEnabled: true,
    cronEnabled: true,
    pangolinEnabled: features.pangolin,
    gerbilEnabled: features.gerbil,
    proxyType: actualProxyType,
    customFlags: {}
  }
  
  return {
    proxyType: actualProxyType,
    containers: config.containers,
    features,
    environment,
    detectedAt: new Date(),
    confidence: config.confidence
  }
})

function renderWhitelistWithDeployment(deployment: DeploymentConfiguration | null) {
  // Set the mock deployment
  mockDeployment = deployment
  
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false }
    }
  })
  
  return render(
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Whitelist />
      </BrowserRouter>
    </QueryClientProvider>
  )
}

describe('Property 5: Proxy-aware whitelist options', () => {
  it('should show CrowdSec whitelist when CrowdSec container is present', () => {
    fc.assert(fc.property(deploymentGenerator, (deployment) => {
      const hasCrowdSec = deployment.containers.some(c => 
        c.name.includes('crowdsec') && c.running
      )
      
      // Skip if no CrowdSec container
      fc.pre(hasCrowdSec)
      
      renderWhitelistWithDeployment(deployment)
      
      // Should always show CrowdSec whitelist section when CrowdSec is present
      expect(screen.getByText('CrowdSec Whitelist')).toBeInTheDocument()
    }), { numRuns: 100 })
  })
  
  it('should show Traefik whitelist options when Traefik container is detected', () => {
    fc.assert(fc.property(deploymentGenerator, (deployment) => {
      const hasTraefik = deployment.containers.some(c => 
        c.name.includes('traefik') && c.running
      )
      
      // Skip if no Traefik container
      fc.pre(hasTraefik)
      
      renderWhitelistWithDeployment(deployment)
      
      // Should show Traefik whitelist section when Traefik is present
      expect(screen.getByText('Traefik Whitelist')).toBeInTheDocument()
      
      // Should show Traefik toggle switches
      expect(screen.getByText('Add to Traefik')).toBeInTheDocument()
    }), { numRuns: 100 })
  })
  
  it('should show proxy-specific whitelist options when other proxy containers are detected', () => {
    fc.assert(fc.property(deploymentGenerator, (deployment) => {
      const hasNonTraefikProxy = deployment.containers.some(c => 
        (c.name.includes('nginx') || c.name.includes('caddy') || 
         c.name.includes('haproxy') || c.name.includes('zoraxy')) && 
        c.running
      )
      
      // Skip if no non-Traefik proxy
      fc.pre(hasNonTraefikProxy)
      
      renderWhitelistWithDeployment(deployment)
      
      // Should show some form of proxy whitelist option
      const proxyContainer = deployment.containers.find(c => 
        (c.name.includes('nginx') || c.name.includes('caddy') || 
         c.name.includes('haproxy') || c.name.includes('zoraxy')) && 
        c.running
      )
      
      if (proxyContainer?.capabilities.includes('whitelist')) {
        // Should show proxy whitelist options if the proxy supports whitelisting
        const proxyName = getProxyDisplayName(proxyContainer.name)
        expect(screen.getByText(`Add to ${proxyName}`)).toBeInTheDocument()
      }
    }), { numRuns: 100 })
  })
  
  it('should show only CrowdSec whitelist when only CrowdSec is running', () => {
    fc.assert(fc.property(deploymentGenerator, (deployment) => {
      const hasCrowdSecOnly = deployment.containers.some(c => 
        c.name.includes('crowdsec') && c.running
      ) && !deployment.containers.some(c => 
        c.role === ContainerRole.PROXY && c.running
      )
      
      // Skip if not CrowdSec-only scenario
      fc.pre(hasCrowdSecOnly)
      
      renderWhitelistWithDeployment(deployment)
      
      // Should show CrowdSec whitelist
      expect(screen.getByText('CrowdSec Whitelist')).toBeInTheDocument()
      
      // Should not show Traefik whitelist section
      expect(screen.queryByText('Traefik Whitelist')).not.toBeInTheDocument()
    }), { numRuns: 100 })
  })
  
  it('should hide proxy whitelist options when proxy containers are removed', () => {
    fc.assert(fc.property(deploymentGenerator, (deployment) => {
      const hasNoRunningProxies = !deployment.containers.some(c => 
        c.role === ContainerRole.PROXY && c.running
      )
      
      // Skip if there are running proxies
      fc.pre(hasNoRunningProxies)
      
      renderWhitelistWithDeployment(deployment)
      
      // Should not show Traefik whitelist section
      expect(screen.queryByText('Traefik Whitelist')).not.toBeInTheDocument()
      
      // Should not show proxy-specific toggle switches
      expect(screen.queryByText('Add to Traefik')).not.toBeInTheDocument()
    }), { numRuns: 100 })
  })
})

// Helper function to get proxy display name
function getProxyDisplayName(containerName: string): string {
  const name = containerName.toLowerCase()
  if (name.includes('traefik')) return 'Traefik'
  if (name.includes('nginx')) return 'Nginx'
  if (name.includes('caddy')) return 'Caddy'
  if (name.includes('haproxy')) return 'HAProxy'
  if (name.includes('zoraxy')) return 'Zoraxy'
  return 'Proxy'
}