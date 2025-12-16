import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Progress } from '@/components/ui/progress'
import { Button } from '@/components/ui/button'
import { 
  Shield, 
  Activity, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Clock,
  Network,
  Database,
  Wifi,
  WifiOff,
  Info,
  RefreshCw
} from 'lucide-react'
import api, { Bouncer } from '@/lib/api'
import { ProxyType } from '@/lib/proxy-types'

interface BouncerStatusMonitorProps {
  proxyType?: ProxyType
  className?: string
}

interface BouncerMetrics {
  totalBouncers: number
  activeBouncers: number
  connectedBouncers: number
  staleBouncers: number
  disconnectedBouncers: number
  lastUpdateTime: Date
}

const getBouncerStatusIcon = (status: string) => {
  switch (status) {
    case 'connected':
      return <CheckCircle2 className="h-4 w-4 text-green-500" />
    case 'stale':
      return <AlertTriangle className="h-4 w-4 text-yellow-500" />
    case 'disconnected':
      return <XCircle className="h-4 w-4 text-red-500" />
    default:
      return <Activity className="h-4 w-4 text-muted-foreground" />
  }
}

const getBouncerStatusBadge = (status: string) => {
  switch (status) {
    case 'connected':
      return <Badge className="bg-green-500">Connected</Badge>
    case 'stale':
      return <Badge className="bg-yellow-500">Stale</Badge>
    case 'disconnected':
      return <Badge variant="destructive">Disconnected</Badge>
    default:
      return <Badge variant="secondary">Unknown</Badge>
  }
}

const getConnectionQuality = (lastPull: Date): { quality: string; percentage: number } => {
  const now = new Date()
  const timeDiff = now.getTime() - lastPull.getTime()
  const minutesAgo = Math.floor(timeDiff / (1000 * 60))

  if (minutesAgo <= 1) {
    return { quality: 'Excellent', percentage: 100 }
  } else if (minutesAgo <= 5) {
    return { quality: 'Good', percentage: 80 }
  } else if (minutesAgo <= 15) {
    return { quality: 'Fair', percentage: 60 }
  } else if (minutesAgo <= 60) {
    return { quality: 'Poor', percentage: 30 }
  } else {
    return { quality: 'Critical', percentage: 10 }
  }
}

const calculateBouncerMetrics = (bouncers: Bouncer[]): BouncerMetrics => {
  const now = new Date()
  let activeBouncers = 0
  let connectedBouncers = 0
  let staleBouncers = 0
  let disconnectedBouncers = 0

  bouncers.forEach(bouncer => {
    const lastPull = new Date(bouncer.last_pull)
    const minutesAgo = Math.floor((now.getTime() - lastPull.getTime()) / (1000 * 60))

    if (minutesAgo <= 5) {
      activeBouncers++
      connectedBouncers++
    } else if (minutesAgo <= 60 && bouncer.valid) {
      staleBouncers++
    } else {
      disconnectedBouncers++
    }
  })

  return {
    totalBouncers: bouncers.length,
    activeBouncers,
    connectedBouncers,
    staleBouncers,
    disconnectedBouncers,
    lastUpdateTime: now
  }
}

const getProxySpecificBouncerInfo = (proxyType: ProxyType) => {
  switch (proxyType) {
    case 'traefik':
      return {
        name: 'Traefik Plugin Bouncer',
        description: 'crowdsec-bouncer-traefik-plugin integration',
        configLocation: 'Dynamic configuration YAML',
        connectionMethod: 'LAPI HTTP'
      }
    case 'nginx':
      return {
        name: 'Nginx Bouncer',
        description: 'cs-nginx-bouncer integration',
        configLocation: 'Nginx configuration',
        connectionMethod: 'LAPI HTTP'
      }
    case 'caddy':
      return {
        name: 'Caddy Bouncer Module',
        description: 'caddy-crowdsec-bouncer module',
        configLocation: 'Caddyfile',
        connectionMethod: 'LAPI HTTP'
      }
    case 'haproxy':
      return {
        name: 'HAProxy SPOA Bouncer',
        description: 'cs-haproxy-bouncer SPOA integration',
        configLocation: 'HAProxy configuration',
        connectionMethod: 'SPOA Socket'
      }
    case 'zoraxy':
      return {
        name: 'Zoraxy Bouncer (Experimental)',
        description: 'Limited bouncer integration',
        configLocation: 'Zoraxy configuration',
        connectionMethod: 'HTTP API'
      }
    case 'standalone':
      return {
        name: 'Standalone Mode',
        description: 'No proxy bouncer integration',
        configLocation: 'N/A',
        connectionMethod: 'Direct LAPI'
      }
    default:
      return {
        name: 'Generic Bouncer',
        description: 'CrowdSec bouncer integration',
        configLocation: 'Configuration files',
        connectionMethod: 'LAPI HTTP'
      }
  }
}

export const BouncerStatusMonitor: React.FC<BouncerStatusMonitorProps> = ({ 
  proxyType = 'traefik',
  className 
}) => {
  const { data: bouncers, isLoading, error, refetch } = useQuery({
    queryKey: ['bouncers'],
    queryFn: async () => {
      const response = await api.crowdsec.getBouncers()
      return response.data.data?.bouncers || []
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  })

  const { data: proxyHealth } = useQuery({
    queryKey: ['proxy-health'],
    queryFn: async () => {
      const response = await api.proxy.checkHealth()
      return response.data.data
    },
    refetchInterval: 5000,
  })

  const { data: bouncerStatus, refetch: refetchBouncerStatus } = useQuery({
    queryKey: ['bouncer-status'],
    queryFn: async () => {
      const response = await api.proxy.getBouncerStatus()
      return response.data.data
    },
    refetchInterval: 10000,
  })

  const validateConfiguration = async () => {
    try {
      await api.proxy.validateBouncerConfiguration()
      // Refresh bouncer status after validation
      refetchBouncerStatus()
    } catch (error) {
      console.error('Configuration validation failed:', error)
    }
  }

  const metrics = bouncers ? calculateBouncerMetrics(bouncers) : null
  const proxyBouncerInfo = getProxySpecificBouncerInfo(proxyType)

  if (error) {
    return (
      <Card className={className}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Bouncer Status Monitor
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Alert variant="destructive">
            <XCircle className="h-4 w-4" />
            <AlertTitle>Connection Error</AlertTitle>
            <AlertDescription>
              Failed to fetch bouncer status. Please check your CrowdSec LAPI connection.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Bouncer Status Monitor</h2>
          <p className="text-muted-foreground">
            Real-time monitoring of CrowdSec bouncer connections and performance
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="p-2 border rounded hover:bg-muted transition-colors"
            disabled={isLoading}
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
          {metrics && (
            <div className="text-sm text-muted-foreground">
              Last updated: {metrics.lastUpdateTime.toLocaleTimeString()}
            </div>
          )}
        </div>
      </div>

      {/* Metrics Overview */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Total Bouncers</p>
                  <p className="text-2xl font-bold">{metrics.totalBouncers}</p>
                </div>
                <Shield className="h-8 w-8 text-blue-500" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Connected</p>
                  <p className="text-2xl font-bold text-green-600">{metrics.connectedBouncers}</p>
                </div>
                <Wifi className="h-8 w-8 text-green-500" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Stale</p>
                  <p className="text-2xl font-bold text-yellow-600">{metrics.staleBouncers}</p>
                </div>
                <AlertTriangle className="h-8 w-8 text-yellow-500" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Disconnected</p>
                  <p className="text-2xl font-bold text-red-600">{metrics.disconnectedBouncers}</p>
                </div>
                <WifiOff className="h-8 w-8 text-red-500" />
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Detailed Status */}
      <Tabs defaultValue="bouncers" className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="bouncers">Active Bouncers</TabsTrigger>
          <TabsTrigger value="proxy">Proxy Integration</TabsTrigger>
          <TabsTrigger value="diagnostics">Diagnostics</TabsTrigger>
        </TabsList>

        {/* Active Bouncers Tab */}
        <TabsContent value="bouncers" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Bouncer Status Details</CardTitle>
              <CardDescription>
                Detailed status and performance metrics for each bouncer
              </CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="space-y-3">
                  {[1, 2, 3].map(i => (
                    <div key={i} className="h-16 bg-muted animate-pulse rounded" />
                  ))}
                </div>
              ) : bouncers && bouncers.length > 0 ? (
                <div className="space-y-4">
                  {bouncers.map((bouncer, index) => {
                    const lastPull = new Date(bouncer.last_pull)
                    const connectionQuality = getConnectionQuality(lastPull)
                    const timeSinceLastPull = Math.floor((Date.now() - lastPull.getTime()) / (1000 * 60))

                    return (
                      <div key={index} className="p-4 border rounded-lg space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            {getBouncerStatusIcon(bouncer.status || 'unknown')}
                            <div>
                              <p className="font-medium">{bouncer.name}</p>
                              <p className="text-sm text-muted-foreground">
                                {bouncer.type} • {bouncer.version}
                              </p>
                            </div>
                          </div>
                          {getBouncerStatusBadge(bouncer.status || 'unknown')}
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                          <div>
                            <p className="text-muted-foreground">IP Address</p>
                            <p className="font-mono">{bouncer.ip_address}</p>
                          </div>
                          <div>
                            <p className="text-muted-foreground">Last Pull</p>
                            <p>{timeSinceLastPull < 1 ? 'Just now' : `${timeSinceLastPull}m ago`}</p>
                          </div>
                          <div>
                            <p className="text-muted-foreground">Valid</p>
                            <p>{bouncer.valid ? 'Yes' : 'No'}</p>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <div className="flex items-center justify-between text-sm">
                            <span>Connection Quality</span>
                            <span className="font-medium">{connectionQuality.quality}</span>
                          </div>
                          <Progress value={connectionQuality.percentage} className="h-2" />
                        </div>
                      </div>
                    )
                  })}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Shield className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <p className="text-muted-foreground">No bouncers connected</p>
                  <p className="text-sm text-muted-foreground mt-2">
                    Configure a bouncer to start monitoring security enforcement
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Proxy Integration Tab */}
        <TabsContent value="proxy" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Network className="h-5 w-5" />
                {proxyBouncerInfo.name}
              </CardTitle>
              <CardDescription>
                {proxyBouncerInfo.description}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-3">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Configuration Location</p>
                    <p className="text-sm">{proxyBouncerInfo.configLocation}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Connection Method</p>
                    <p className="text-sm">{proxyBouncerInfo.connectionMethod}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Bouncer Support</p>
                    <div className="flex items-center gap-2">
                      {bouncerStatus?.supported ? (
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                      ) : (
                        <XCircle className="h-4 w-4 text-red-500" />
                      )}
                      <span className="text-sm">
                        {bouncerStatus?.supported ? 'Supported' : 'Not Supported'}
                      </span>
                    </div>
                    {!bouncerStatus?.supported && bouncerStatus?.reason && (
                      <p className="text-xs text-muted-foreground mt-1">{bouncerStatus.reason}</p>
                    )}
                  </div>
                </div>
                
                <div className="space-y-3">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Proxy Status</p>
                    <div className="flex items-center gap-2">
                      {proxyHealth?.status === 'healthy' ? (
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                      ) : (
                        <XCircle className="h-4 w-4 text-red-500" />
                      )}
                      <span className="text-sm capitalize">{proxyHealth?.status || 'Unknown'}</span>
                    </div>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Configuration Status</p>
                    <div className="flex items-center gap-2">
                      {bouncerStatus?.configured ? (
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                      ) : (
                        <AlertTriangle className="h-4 w-4 text-yellow-500" />
                      )}
                      <span className="text-sm">
                        {bouncerStatus?.configured ? 'Configured' : 'Not Configured'}
                      </span>
                    </div>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Integration Status</p>
                    <div className="flex items-center gap-2">
                      {metrics && metrics.connectedBouncers > 0 ? (
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                      ) : (
                        <AlertTriangle className="h-4 w-4 text-yellow-500" />
                      )}
                      <span className="text-sm">
                        {metrics && metrics.connectedBouncers > 0 ? 'Active' : 'No Active Bouncers'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Configuration Verification */}
              {bouncerStatus?.supported && (
                <div className="border-t pt-4">
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-sm font-medium">Configuration Verification</h4>
                    <button
                      onClick={validateConfiguration}
                      className="px-3 py-1 text-xs border rounded hover:bg-muted transition-colors"
                    >
                      Validate Configuration
                    </button>
                  </div>
                  
                  {bouncerStatus?.status && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>Integration Type:</span>
                        <span className="font-medium">{bouncerStatus.status.integration_type || 'Unknown'}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span>LAPI Connection:</span>
                        <div className="flex items-center gap-1">
                          {bouncerStatus.status.lapi_connected ? (
                            <CheckCircle2 className="h-3 w-3 text-green-500" />
                          ) : (
                            <XCircle className="h-3 w-3 text-red-500" />
                          )}
                          <span className="font-medium">
                            {bouncerStatus.status.lapi_connected ? 'Connected' : 'Disconnected'}
                          </span>
                        </div>
                      </div>
                      {bouncerStatus.status.bouncer_name && (
                        <div className="flex justify-between text-sm">
                          <span>Bouncer Name:</span>
                          <span className="font-medium font-mono text-xs">{bouncerStatus.status.bouncer_name}</span>
                        </div>
                      )}
                      {bouncerStatus.status.last_seen && (
                        <div className="flex justify-between text-sm">
                          <span>Last Seen:</span>
                          <span className="font-medium">{new Date(bouncerStatus.status.last_seen).toLocaleString()}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {proxyType === 'zoraxy' && (
                <Alert>
                  <Info className="h-4 w-4" />
                  <AlertDescription>
                    Zoraxy bouncer integration is experimental. Limited monitoring features are available.
                  </AlertDescription>
                </Alert>
              )}

              {proxyType === 'standalone' && (
                <Alert>
                  <Info className="h-4 w-4" />
                  <AlertDescription>
                    Standalone mode does not include proxy-level bouncer integration. 
                    CrowdSec operates independently without reverse proxy enforcement.
                  </AlertDescription>
                </Alert>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Diagnostics Tab */}
        <TabsContent value="diagnostics" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-5 w-5" />
                LAPI Connection Diagnostics
              </CardTitle>
              <CardDescription>
                Detailed analysis of CrowdSec Local API connections and bouncer performance
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {metrics ? (
                <div className="space-y-4">
                  {/* Proxy-Specific Bouncer Status */}
                  {bouncerStatus?.supported && (
                    <div className="p-4 border rounded-lg bg-muted/50">
                      <h4 className="text-sm font-medium mb-3 flex items-center gap-2">
                        <Network className="h-4 w-4" />
                        {proxyBouncerInfo.name} Integration
                      </h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        <div className="space-y-2">
                          <div className="flex justify-between">
                            <span>Configuration Status:</span>
                            <Badge variant={bouncerStatus.configured ? 'default' : 'secondary'}>
                              {bouncerStatus.configured ? 'Configured' : 'Not Configured'}
                            </Badge>
                          </div>
                          {bouncerStatus.status?.integration_type && (
                            <div className="flex justify-between">
                              <span>Integration Type:</span>
                              <span className="font-medium">{bouncerStatus.status.integration_type}</span>
                            </div>
                          )}
                          {bouncerStatus.status?.bouncer_name && (
                            <div className="flex justify-between">
                              <span>Bouncer Name:</span>
                              <span className="font-mono text-xs">{bouncerStatus.status.bouncer_name}</span>
                            </div>
                          )}
                        </div>
                        <div className="space-y-2">
                          <div className="flex justify-between">
                            <span>LAPI Connection:</span>
                            <div className="flex items-center gap-1">
                              {bouncerStatus.status?.lapi_connected ? (
                                <CheckCircle2 className="h-3 w-3 text-green-500" />
                              ) : (
                                <XCircle className="h-3 w-3 text-red-500" />
                              )}
                              <span className="font-medium">
                                {bouncerStatus.status?.lapi_connected ? 'Connected' : 'Disconnected'}
                              </span>
                            </div>
                          </div>
                          {bouncerStatus.status?.last_seen && (
                            <div className="flex justify-between">
                              <span>Last Activity:</span>
                              <span className="font-medium">
                                {new Date(bouncerStatus.status.last_seen).toLocaleString()}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-3 border rounded-lg">
                      <p className="text-sm font-medium mb-2">Connection Health</p>
                      <div className="space-y-2">
                        <div className="flex justify-between text-sm">
                          <span>Active Connections:</span>
                          <span className="font-medium text-green-600">{metrics.connectedBouncers}</span>
                        </div>
                        <div className="flex justify-between text-sm">
                          <span>Stale Connections:</span>
                          <span className="font-medium text-yellow-600">{metrics.staleBouncers}</span>
                        </div>
                        <div className="flex justify-between text-sm">
                          <span>Failed Connections:</span>
                          <span className="font-medium text-red-600">{metrics.disconnectedBouncers}</span>
                        </div>
                      </div>
                    </div>

                    <div className="p-3 border rounded-lg">
                      <p className="text-sm font-medium mb-2">Performance Metrics</p>
                      <div className="space-y-2">
                        <div className="flex justify-between text-sm">
                          <span>Uptime Ratio:</span>
                          <span className="font-medium">
                            {metrics.totalBouncers > 0 
                              ? Math.round((metrics.connectedBouncers / metrics.totalBouncers) * 100)
                              : 0
                            }%
                          </span>
                        </div>
                        <div className="flex justify-between text-sm">
                          <span>Response Quality:</span>
                          <span className="font-medium">
                            {metrics.connectedBouncers > 0 ? 'Good' : 'Poor'}
                          </span>
                        </div>
                        <div className="flex justify-between text-sm">
                          <span>Connection Method:</span>
                          <span className="font-medium">{proxyBouncerInfo.connectionMethod}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Connection Timeline */}
                  <div className="p-3 border rounded-lg">
                    <div className="flex items-center justify-between mb-3">
                      <p className="text-sm font-medium">Recent Activity</p>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => refetch()}
                        disabled={isLoading}
                      >
                        <RefreshCw className={`h-3 w-3 mr-1 ${isLoading ? 'animate-spin' : ''}`} />
                        Refresh
                      </Button>
                    </div>
                    <div className="space-y-2">
                      {bouncers && bouncers.slice(0, 5).map((bouncer, index) => {
                        const lastPull = new Date(bouncer.last_pull)
                        const timeSinceLastPull = Math.floor((Date.now() - lastPull.getTime()) / (1000 * 60))
                        
                        return (
                          <div key={index} className="flex items-center justify-between text-sm p-2 rounded bg-muted/30">
                            <div className="flex items-center gap-2">
                              {getBouncerStatusIcon(bouncer.status || 'unknown')}
                              <div>
                                <span className="font-medium">{bouncer.name}</span>
                                <p className="text-xs text-muted-foreground">{bouncer.type} • {bouncer.ip_address}</p>
                              </div>
                            </div>
                            <div className="flex items-center gap-2 text-muted-foreground">
                              <Clock className="h-3 w-3" />
                              <span>{timeSinceLastPull < 1 ? 'Just now' : `${timeSinceLastPull}m ago`}</span>
                            </div>
                          </div>
                        )
                      })}
                      {(!bouncers || bouncers.length === 0) && (
                        <div className="text-center py-4 text-muted-foreground">
                          <WifiOff className="h-8 w-8 mx-auto mb-2" />
                          <p className="text-sm">No bouncer activity detected</p>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Troubleshooting Tips */}
                  {metrics.connectedBouncers === 0 && (
                    <Alert>
                      <AlertTriangle className="h-4 w-4" />
                      <AlertTitle>No Active Bouncers Detected</AlertTitle>
                      <AlertDescription>
                        <div className="mt-2 space-y-1 text-sm">
                          <p>• Verify that your {proxyType} bouncer is properly configured</p>
                          <p>• Check that the LAPI key is correctly set in {proxyBouncerInfo.configLocation}</p>
                          <p>• Ensure the CrowdSec container is running and accessible</p>
                          <p>• Review {proxyType} logs for connection errors</p>
                        </div>
                      </AlertDescription>
                    </Alert>
                  )}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Activity className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <p className="text-muted-foreground">Loading diagnostic information...</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}

export default BouncerStatusMonitor