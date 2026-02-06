import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ProxyType, Feature, ProxyStatus, ProxyInfo, PROXY_TYPES } from '@/lib/proxy-types'
import api from '@/lib/api'

interface ProxyContextType {
  proxyType: ProxyType
  proxyInfo: ProxyInfo | null
  supportedFeatures: Feature[]
  proxyStatus: ProxyStatus | null
  isLoading: boolean
  error: string | null
  refreshProxyInfo: () => void
}

const ProxyContext = createContext<ProxyContextType | undefined>(undefined)

interface ProxyProviderProps {
  children: ReactNode
}

export function ProxyProvider({ children }: ProxyProviderProps) {
  const [proxyType, setProxyType] = useState<ProxyType>('traefik') // Default fallback
  const [supportedFeatures, setSupportedFeatures] = useState<Feature[]>([])

  // Query proxy information from the API
  const { 
    data: proxyData, 
    isLoading, 
    error, 
    refetch: refreshProxyInfo 
  } = useQuery({
    queryKey: ['proxy-info'],
    queryFn: async () => {
      try {
        // Use the new proxy API endpoint
        const response = await api.proxy.getCurrent()
        
        if (response.data.success && response.data.data) {
          const data = response.data.data
          return {
            type: data.type as ProxyType,
            running: data.running,
            connected: data.connected,
            features: data.supported_features as Feature[]
          }
        }
        
        // Fallback to standalone mode
        return {
          type: 'standalone' as ProxyType,
          running: true,
          connected: false,
          features: ['health'] as Feature[]
        }
      } catch {
        // If proxy API fails, fall back to standalone mode
        return {
          type: 'standalone' as ProxyType,
          running: false,
          connected: false,
          features: ['health'] as Feature[]
        }
      }
    },
    retry: 1,
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  // Update proxy type and features when data changes
  useEffect(() => {
    if (proxyData) {
      setProxyType(proxyData.type)
      setSupportedFeatures(proxyData.features)
    }
  }, [proxyData])

  // Get proxy info from constants
  const proxyInfo = PROXY_TYPES.find(p => p.type === proxyType) || null

  // Create proxy status object
  const proxyStatus: ProxyStatus | null = proxyData ? {
    type: proxyData.type,
    running: proxyData.running,
    connected: proxyData.connected,
    containerName: proxyData.type === 'traefik' ? 'traefik' : proxyData.type,
    healthStatus: proxyData.running ? 'healthy' : 'unhealthy'
  } : null

  const contextValue: ProxyContextType = {
    proxyType,
    proxyInfo,
    supportedFeatures,
    proxyStatus,
    isLoading,
    error: error?.message || null,
    refreshProxyInfo
  }

  return (
    <ProxyContext.Provider value={contextValue}>
      {children}
    </ProxyContext.Provider>
  )
}

export function useProxy(): ProxyContextType {
  const context = useContext(ProxyContext)
  if (context === undefined) {
    throw new Error('useProxy must be used within a ProxyProvider')
  }
  return context
}

// Helper hook for feature detection
export function useFeature(feature: Feature): boolean {
  const { supportedFeatures } = useProxy()
  return supportedFeatures.includes(feature)
}

// Helper hook for proxy-specific behavior
export function useProxyCapabilities() {
  const { proxyType, supportedFeatures } = useProxy()
  
  return {
    supportsLogs: supportedFeatures.includes('logs'),
    supportsWhitelist: supportedFeatures.includes('whitelist'),
    supportsCaptcha: supportedFeatures.includes('captcha'),
    supportsBouncer: supportedFeatures.includes('bouncer'),
    supportsAppsec: supportedFeatures.includes('appsec'),
    isTraefik: proxyType === 'traefik',
    isNginx: proxyType === 'nginx',
    isCaddy: proxyType === 'caddy',
    isHAProxy: proxyType === 'haproxy',
    isZoraxy: proxyType === 'zoraxy',
    isStandalone: proxyType === 'standalone',
    proxyName: proxyType.charAt(0).toUpperCase() + proxyType.slice(1)
  }
}