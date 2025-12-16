import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { 
  Activity, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Info,
  Network,
  Server,
  Shield,
  Zap,
  Database
} from 'lucide-react'
import api from '@/lib/api'
import { ProxyType } from '@/lib/proxy-types'

interface ProxyHealthIndicatorProps {
  proxyType: ProxyType
  className?: string
}

const getProxyIcon = (proxyType: ProxyType) => {
  switch (proxyType) {
    case 'traefik':
      return Network
    case 'nginx':
      return Server
    case 'caddy':
      return Shield
    case 'haproxy':
      return Activity
    case 'zoraxy':
      return Zap
    case 'standalone':
      return Database
    default:
      return Activity
  }
}

const getProxyDisplayName = (proxyType: ProxyType): string => {
  switch (proxyType) {
    case 'traefik':
      return 'Traefik'
    case 'nginx':
      return 'Nginx Proxy Manager'
    case 'caddy':
      return 'Caddy'
    case 'haproxy':
      return 'HAProxy'
    case 'zoraxy':
      return 'Zoraxy'
    case 'standalone':
      return 'Standalone Mode'
    default:
      return 'Unknown'
  }
}

const getStatusIcon = (status: string) => {
  switch (status) {
    case 'healthy':
      return <CheckCircle2 className="h-4 w-4 text-green-500" />
    case 'unhealthy':
      return <XCircle className="h-4 w-4 text-red-500" />
    case 'degraded':
      return <AlertTriangle className="h-4 w-4 text-yellow-500" />
    case 'warning':
      return <AlertTriangle className="h-4 w-4 text-orange-500" />
    case 'info':
      return <Info className="h-4 w-4 text-blue-500" />
    default:
      return <Activity className="h-4 w-4 text-muted-foreground" />
  }
}

const getStatusBadge = (status: string) => {
  switch (status) {
    case 'healthy':
      return <Badge className="bg-green-500">Healthy</Badge>
    case 'unhealthy':
      return <Badge variant="destructive">Unhealthy</Badge>
    case 'degraded':
      return <Badge className="bg-yellow-500">Degraded</Badge>
    case 'warning':
      return <Badge className="bg-orange-500">Warning</Badge>
    case 'info':
      return <Badge variant="outline">Info</Badge>
    default:
      return <Badge variant="secondary">Unknown</Badge>
  }
}

export const ProxyHealthIndicator: React.FC<ProxyHealthIndicatorProps> = ({ 
  proxyType, 
  className 
}) => {
  const ProxyIcon = getProxyIcon(proxyType)
  
  const { data: healthData, isLoading, error } = useQuery({
    queryKey: ['proxy-health', proxyType],
    queryFn: async () => {
      const response = await api.proxy.checkHealth()
      return response.data.data
    },
    refetchInterval: 5000, // Refresh every 5 seconds
  })

  const { data: proxyInfo } = useQuery({
    queryKey: ['proxy-current'],
    queryFn: async () => {
      const response = await api.proxy.getCurrent()
      return response.data.data
    },
  })

  if (error) {
    return (
      <Card className={className}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ProxyIcon className="h-5 w-5" />
            {getProxyDisplayName(proxyType)} Health
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Alert variant="destructive">
            <XCircle className="h-4 w-4" />
            <AlertDescription>
              Failed to fetch proxy health status. Please check your connection.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ProxyIcon className="h-5 w-5" />
          {getProxyDisplayName(proxyType)} Health
        </CardTitle>
        <CardDescription>
          Real-time health monitoring for {getProxyDisplayName(proxyType)}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {isLoading ? (
          <div className="flex items-center justify-center p-4">
            <Activity className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : (
          <>
            {/* Overall Status */}
            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div className="flex items-center gap-2">
                {getStatusIcon(healthData?.status || 'unknown')}
                <div>
                  <p className="font-medium">Overall Status</p>
                  <p className="text-sm text-muted-foreground">
                    {healthData?.details?.message || 'No status information available'}
                  </p>
                </div>
              </div>
              {getStatusBadge(healthData?.status || 'unknown')}
            </div>

            {/* Container Status */}
            {proxyInfo && (
              <div className="flex items-center justify-between p-3 border rounded-lg">
                <div className="flex items-center gap-2">
                  {proxyInfo.running ? (
                    <CheckCircle2 className="h-4 w-4 text-green-500" />
                  ) : (
                    <XCircle className="h-4 w-4 text-red-500" />
                  )}
                  <div>
                    <p className="font-medium">Container Status</p>
                    <p className="text-sm text-muted-foreground">
                      {proxyInfo.container_name}
                    </p>
                  </div>
                </div>
                <Badge variant={proxyInfo.running ? 'default' : 'destructive'}>
                  {proxyInfo.running ? 'Running' : 'Stopped'}
                </Badge>
              </div>
            )}

            {/* Connection Status */}
            {proxyInfo && (
              <div className="flex items-center justify-between p-3 border rounded-lg">
                <div className="flex items-center gap-2">
                  {proxyInfo.connected ? (
                    <CheckCircle2 className="h-4 w-4 text-green-500" />
                  ) : (
                    <AlertTriangle className="h-4 w-4 text-yellow-500" />
                  )}
                  <div>
                    <p className="font-medium">Connection Status</p>
                    <p className="text-sm text-muted-foreground">
                      {proxyInfo.connected ? 'Connected and responsive' : 'Connection issues detected'}
                    </p>
                  </div>
                </div>
                <Badge variant={proxyInfo.connected ? 'default' : 'secondary'}>
                  {proxyInfo.connected ? 'Connected' : 'Disconnected'}
                </Badge>
              </div>
            )}

            {/* Supported Features */}
            {proxyInfo?.supported_features && proxyInfo.supported_features.length > 0 && (
              <div className="p-3 border rounded-lg">
                <p className="font-medium mb-2">Supported Features</p>
                <div className="flex flex-wrap gap-1">
                  {proxyInfo.supported_features.map((feature) => (
                    <Badge key={feature} variant="outline" className="text-xs">
                      {feature}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* Health Details */}
            {healthData?.details && (
              <div className="p-3 border rounded-lg">
                <p className="font-medium mb-2">Health Details</p>
                <div className="space-y-2">
                  {Object.entries(healthData.details).map(([key, value]) => (
                    <div key={key} className="flex justify-between text-sm">
                      <span className="text-muted-foreground capitalize">
                        {key.replace(/_/g, ' ')}:
                      </span>
                      <span className="font-mono">
                        {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Experimental Warning */}
            {proxyType === 'zoraxy' && (
              <Alert>
                <Info className="h-4 w-4" />
                <AlertDescription>
                  Zoraxy integration is experimental. Limited health monitoring features are available.
                </AlertDescription>
              </Alert>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}

export default ProxyHealthIndicator