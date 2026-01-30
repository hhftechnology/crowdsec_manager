import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import api from '@/lib/api'
import { 
  ContainerInfo, ContainerStatus, ContainerRole, HealthStatus, 
  FeatureAvailability, EnvironmentFlags, DeploymentConfiguration 
} from '@/lib/deployment-types'
import { detectFeatures } from '@/lib/feature-detector'



interface DeploymentContextType {
  deployment: DeploymentConfiguration | null
  isLoading: boolean
  error: string | null
  refreshDeployment: () => void
}

const DeploymentContext = createContext<DeploymentContextType | undefined>(undefined)

interface DeploymentProviderProps {
  children: ReactNode
}

export function DeploymentProvider({ children }: DeploymentProviderProps) {
  const [deployment, setDeployment] = useState<DeploymentConfiguration | null>(null)

  // Query deployment information from the API
  const { 
    data: deploymentData, 
    isLoading, 
    error, 
    refetch: refreshDeployment 
  } = useQuery({
    queryKey: ['deployment-info'],
    queryFn: async () => {
      try {
        // Get container information from health endpoint
        const healthResponse = await api.health.checkStack()
        const containers: ContainerInfo[] = []
        
        if (healthResponse.data.success && healthResponse.data.data?.containers) {
          for (const container of healthResponse.data.data.containers) {
            const containerInfo: ContainerInfo = {
              name: container.name,
              id: container.id || '',
              status: mapContainerStatus(container.status),
              running: container.running,
              capabilities: determineContainerCapabilities(container.name, container.running),
              role: determineContainerRole(container.name),
              healthStatus: container.running ? HealthStatus.HEALTHY : HealthStatus.UNHEALTHY
            }
            containers.push(containerInfo)
          }
        }

        // Get proxy information
        let proxyType: string | null = null
        try {
          const proxyResponse = await api.proxy.getCurrent()
          if (proxyResponse.data.success && proxyResponse.data.data) {
            proxyType = proxyResponse.data.data.type
          }
        } catch (proxyError) {
          // Fallback to detecting from containers
          proxyType = detectProxyTypeFromContainers(containers)
        }

        // Get environment flags (simulated for now - would need backend endpoint)
        const environmentFlags: EnvironmentFlags = {
          backupEnabled: true, // Default assumption
          cronEnabled: true,   // Default assumption
          pangolinEnabled: containers.some(c => c.name.includes('pangolin') && c.running),
          gerbilEnabled: containers.some(c => c.name.includes('gerbil') && c.running),
          proxyType: proxyType || 'standalone',
          customFlags: {}
        }

        // Determine feature availability using the centralized detector
        const features = detectFeatures(containers, environmentFlags)

        // Calculate confidence based on successful detections
        let confidence = 0.5 // Base confidence
        if (proxyType) confidence += 0.2
        if (containers.length > 0) confidence += 0.2
        if (containers.some(c => c.running)) confidence += 0.1
        confidence = Math.min(confidence, 1.0)

        const deploymentConfig: DeploymentConfiguration = {
          proxyType,
          containers,
          features,
          environment: environmentFlags,
          detectedAt: new Date(),
          confidence
        }

        return deploymentConfig
      } catch (error) {
        console.error('Failed to detect deployment configuration:', error)
        throw error
      }
    },
    retry: 2,
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  // Update deployment state when data changes
  useEffect(() => {
    if (deploymentData) {
      setDeployment(deploymentData)
    }
  }, [deploymentData])

  const contextValue: DeploymentContextType = {
    deployment,
    isLoading,
    error: error?.message || null,
    refreshDeployment
  }

  return (
    <DeploymentContext.Provider value={contextValue}>
      {children}
    </DeploymentContext.Provider>
  )
}

export function useDeployment(): DeploymentContextType {
  const context = useContext(DeploymentContext)
  if (context === undefined) {
    throw new Error('useDeployment must be used within a DeploymentProvider')
  }
  return context
}

// Helper functions for container analysis
function mapContainerStatus(status: string): ContainerStatus {
  switch (status.toLowerCase()) {
    case 'running':
      return ContainerStatus.RUNNING
    case 'stopped':
    case 'exited':
      return ContainerStatus.STOPPED
    case 'restarting':
      return ContainerStatus.RESTARTING
    default:
      return ContainerStatus.UNKNOWN
  }
}

function determineContainerRole(containerName: string): ContainerRole {
  const name = containerName.toLowerCase()
  
  if (name.includes('traefik') || name.includes('nginx') || name.includes('caddy') || 
      name.includes('haproxy') || name.includes('zoraxy')) {
    return ContainerRole.PROXY
  }
  
  if (name.includes('crowdsec')) {
    return ContainerRole.SECURITY
  }
  
  if (name.includes('pangolin') || name.includes('gerbil')) {
    return ContainerRole.ADDON
  }
  
  return ContainerRole.MONITORING
}

function determineContainerCapabilities(containerName: string, running: boolean): string[] {
  if (!running) return []
  
  const name = containerName.toLowerCase()
  const capabilities: string[] = ['health'] // All containers have health capability
  
  if (name.includes('traefik')) {
    capabilities.push('whitelist', 'captcha', 'logs', 'bouncer', 'appsec')
  } else if (name.includes('nginx')) {
    capabilities.push('whitelist', 'logs', 'bouncer')
  } else if (name.includes('caddy')) {
    capabilities.push('whitelist', 'logs', 'bouncer')
  } else if (name.includes('haproxy')) {
    capabilities.push('whitelist', 'logs', 'bouncer')
  } else if (name.includes('crowdsec')) {
    capabilities.push('bouncer', 'logs')
  } else if (name.includes('pangolin') || name.includes('gerbil')) {
    capabilities.push('logs')
  }
  
  return capabilities
}

function detectProxyTypeFromContainers(containers: ContainerInfo[]): string | null {
  const runningProxies = containers.filter(c => 
    c.role === ContainerRole.PROXY && c.running
  )
  
  if (runningProxies.length === 0) {
    return 'standalone'
  }
  
  // Return the first detected proxy type
  const proxyContainer = runningProxies[0]
  const name = proxyContainer.name.toLowerCase()
  
  if (name.includes('traefik')) return 'traefik'
  if (name.includes('nginx')) return 'nginx'
  if (name.includes('caddy')) return 'caddy'
  if (name.includes('haproxy')) return 'haproxy'
  if (name.includes('zoraxy')) return 'zoraxy'
  
  return 'standalone'
}

// Helper hooks for specific deployment aspects
export function useContainers(): ContainerInfo[] {
  const { deployment } = useDeployment()
  return deployment?.containers || []
}

export function useRunningContainers(): ContainerInfo[] {
  const containers = useContainers()
  return containers.filter(c => c.running)
}

export function useFeatures(): FeatureAvailability {
  const { deployment } = useDeployment()
  return deployment?.features || {
    captcha: false,
    backup: false,
    cronJobs: false,
    whitelistProxy: false,
    logs: false,
    pangolin: false,
    gerbil: false,
    appsec: false,
    bouncer: false,
    addons: false
  }
}

export function useFeature(feature: keyof FeatureAvailability): boolean {
  const features = useFeatures()
  return features[feature]
}

export function useProxyType(): string | null {
  const { deployment } = useDeployment()
  return deployment?.proxyType || null
}

export function useEnvironmentFlags(): EnvironmentFlags {
  const { deployment } = useDeployment()
  return deployment?.environment || {
    backupEnabled: false,
    cronEnabled: false,
    pangolinEnabled: false,
    gerbilEnabled: false,
    proxyType: 'standalone',
    customFlags: {}
  }
}