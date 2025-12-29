import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { StatusCard } from '@/components/common/StatusCard'
import { 
  Activity, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle,
  Shield,
  Network,
  Database,
  BarChart3,
  Clock,
  RefreshCw
} from 'lucide-react'
import api from '@/lib/api'
import { ProxyType } from '@/lib/proxy-types'
import { useDeployment, useRunningContainers, useContainers, useProxyType } from '@/contexts/DeploymentContext'
import ProxyHealthIndicator from './ProxyHealthIndicator'

interface StatusDashboardProps {
  className?: string
}

export const StatusDashboard: React.FC<StatusDashboardProps> = ({ className }) => {
  const { isLoading: deploymentLoading } = useDeployment()
  const runningContainers = useRunningContainers()
  const allContainers = useContainers()
  const proxyType = useProxyType()

  // Fetch comprehensive health data
  const { data: healthData, isLoading: healthLoading } = useQuery({
    queryKey: ['health-stack'],
    queryFn: async () => {
      const response = await api.health.checkStack()
      return response.data.data
    },
    refetchInterval: 5000,
  })

  const { data: crowdsecHealth, isLoading: crowdsecLoading } = useQuery({
    queryKey: ['crowdsec-health'],
    queryFn: async () => {
      const response = await api.health.crowdsecHealth()
      return response.data.data
    },
    refetchInterval: 5000,
  })

  const { data: diagnostics, isLoading: diagnosticsLoading } = useQuery({
    queryKey: ['diagnostics'],
    queryFn: async () => {
      const response = await api.health.completeDiagnostics()
      return response.data.data
    },
    refetchInterval: 10000,
  })

  const { data: proxyInfo } = useQuery({
    queryKey: ['proxy-current'],
    queryFn: async () => {
      const response = await api.proxy.getCurrent()
      return response.data.data
    },
  })

  const isLoading = healthLoading || crowdsecLoading || diagnosticsLoading || deploymentLoading

  // Use deployment-aware container counts
  const runningContainerCount = runningContainers.length
  const totalContainerCount = allContainers.length
  const allRunning = runningContainerCount === totalContainerCount && totalContainerCount > 0
  const activeBouncer = diagnostics?.bouncers?.length || 0
  const totalDecisions = diagnostics?.decisions?.length || 0

  // Group containers by role for better organization
  const containersByRole = allContainers.reduce((acc, container) => {
    if (!acc[container.role]) {
      acc[container.role] = []
    }
    acc[container.role].push(container)
    return acc
  }, {} as Record<string, typeof allContainers>)

  // Determine overall system health
  const getOverallHealth = () => {
    if (!healthData || !crowdsecHealth) return 'unknown'
    
    if (!allRunning || crowdsecHealth.status === 'unhealthy') {
      return 'error'
    }
    
    if (crowdsecHealth.status === 'degraded') {
      return 'warning'
    }
    
    return 'success'
  }

  const overallHealth = getOverallHealth()

  return (
    <div className={`space-y-6 ${className}`}>
      {/* System Status Overview */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-2xl font-bold">System Status Dashboard</h2>
            <p className="text-muted-foreground">
              Real-time monitoring of all system components
            </p>
          </div>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Clock className="h-4 w-4" />
            {healthData?.timestamp && (
              <span>Last updated: {new Date(healthData.timestamp).toLocaleTimeString()}</span>
            )}
          </div>
        </div>

        {/* Status Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatusCard
            title="System Health"
            value={overallHealth === 'success' ? 'Healthy' : overallHealth === 'error' ? 'Critical' : 'Warning'}
            icon={overallHealth === 'success' ? CheckCircle2 : overallHealth === 'error' ? XCircle : AlertTriangle}
            status={overallHealth === 'unknown' ? 'info' : overallHealth}
            description="Overall system status"
            loading={isLoading}
          />
          
          <StatusCard
            title="Containers"
            value={`${runningContainerCount}/${totalContainerCount}`}
            icon={Network}
            status={allRunning ? 'success' : runningContainerCount > 0 ? 'warning' : 'error'}
            description="Running containers in deployment"
            loading={isLoading}
          />
          
          <StatusCard
            title="Active Bouncers"
            value={activeBouncer}
            icon={Shield}
            status={activeBouncer > 0 ? 'success' : 'warning'}
            description="Connected security agents"
            loading={diagnosticsLoading}
          />
          
          <StatusCard
            title="Security Decisions"
            value={totalDecisions}
            icon={BarChart3}
            status="info"
            description="Active security decisions"
            loading={diagnosticsLoading}
          />
        </div>
      </div>

      {/* Detailed Status Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="containers">Containers</TabsTrigger>
          <TabsTrigger value="proxy">Proxy Health</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* System Health Summary */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5" />
                  Deployment Health Summary
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {isLoading ? (
                  <div className="space-y-2">
                    <div className="h-4 bg-muted animate-pulse rounded" />
                    <div className="h-4 bg-muted animate-pulse rounded" />
                  </div>
                ) : (
                  <>
                    <div className="flex items-center justify-between">
                      <span>CrowdSec Engine</span>
                      <Badge variant={crowdsecHealth?.status === 'healthy' ? 'default' : 'destructive'}>
                        {crowdsecHealth?.status || 'Unknown'}
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Container Stack</span>
                      <Badge variant={allRunning ? 'default' : 'destructive'}>
                        {allRunning ? 'All Running' : 'Issues Detected'}
                      </Badge>
                    </div>
                    {proxyInfo && (
                      <div className="flex items-center justify-between">
                        <span>Proxy Integration</span>
                        <Badge variant={proxyInfo.connected ? 'default' : 'secondary'}>
                          {proxyInfo.type.charAt(0).toUpperCase() + proxyInfo.type.slice(1)}
                        </Badge>
                      </div>
                    )}
                    <div className="flex items-center justify-between">
                      <span>Deployment Type</span>
                      <Badge variant="outline">
                        {(proxyType?.charAt(0).toUpperCase() || '') + (proxyType?.slice(1) || 'Unknown')}
                      </Badge>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            {/* Quick Actions */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <RefreshCw className="h-5 w-5" />
                  Quick Actions
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="grid grid-cols-2 gap-2">
                  <button 
                    className="p-2 text-sm border rounded hover:bg-muted transition-colors"
                    onClick={() => window.location.reload()}
                  >
                    Refresh Status
                  </button>
                  <button 
                    className="p-2 text-sm border rounded hover:bg-muted transition-colors"
                    onClick={() => window.open('/health', '_blank')}
                  >
                    Full Diagnostics
                  </button>
                  <button 
                    className="p-2 text-sm border rounded hover:bg-muted transition-colors"
                    onClick={() => window.open('/crowdsec-health', '_blank')}
                  >
                    CrowdSec Health
                  </button>
                  <button 
                    className="p-2 text-sm border rounded hover:bg-muted transition-colors"
                    onClick={() => window.open('/logs', '_blank')}
                  >
                    View Logs
                  </button>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Containers Tab */}
        <TabsContent value="containers" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Deployment Container Status</CardTitle>
              <CardDescription>
                Status of containers in current deployment grouped by role
              </CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="space-y-2">
                  <div className="h-16 bg-muted animate-pulse rounded" />
                  <div className="h-16 bg-muted animate-pulse rounded" />
                </div>
              ) : allContainers.length > 0 ? (
                <div className="space-y-6">
                  {Object.entries(containersByRole).map(([role, containers]) => (
                    containers.length > 0 && (
                      <div key={role} className="space-y-3">
                        <div className="flex items-center gap-2">
                          <div className="h-2 w-2 rounded-full bg-primary" />
                          <h4 className="text-sm font-medium capitalize">
                            {role} Containers ({containers.length})
                          </h4>
                        </div>
                        <div className="space-y-2">
                          {containers.map((container) => (
                            <div key={container.id} className="flex items-center justify-between p-3 border rounded-lg">
                              <div className="flex items-center gap-3">
                                {container.running ? (
                                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                                ) : (
                                  <XCircle className="h-5 w-5 text-red-500" />
                                )}
                                <div>
                                  <p className="font-medium">{container.name}</p>
                                  <p className="text-sm text-muted-foreground font-mono">
                                    {container.id.substring(0, 12)}
                                  </p>
                                </div>
                              </div>
                              <div className="flex items-center gap-2">
                                <Badge variant={container.running ? 'default' : 'destructive'}>
                                  {container.status}
                                </Badge>
                                {container.capabilities.length > 0 && (
                                  <div className="flex flex-wrap gap-1">
                                    {container.capabilities.slice(0, 3).map((capability) => (
                                      <Badge key={capability} variant="outline" className="text-xs">
                                        {capability}
                                      </Badge>
                                    ))}
                                    {container.capabilities.length > 3 && (
                                      <Badge variant="outline" className="text-xs">
                                        +{container.capabilities.length - 3}
                                      </Badge>
                                    )}
                                  </div>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )
                  ))}
                </div>
              ) : (
                <p className="text-muted-foreground text-center py-8">
                  No containers detected in current deployment
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Proxy Health Tab */}
        <TabsContent value="proxy" className="space-y-4">
          {proxyInfo ? (
            <ProxyHealthIndicator proxyType={proxyInfo.type as ProxyType} />
          ) : (
            <Card>
              <CardContent className="p-6">
                <div className="text-center">
                  <Activity className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <p className="text-muted-foreground">Loading proxy information...</p>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Security Tab */}
        <TabsContent value="security" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Bouncers Status */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Active Bouncers
                </CardTitle>
              </CardHeader>
              <CardContent>
                {diagnosticsLoading ? (
                  <div className="space-y-2">
                    <div className="h-4 bg-muted animate-pulse rounded" />
                    <div className="h-4 bg-muted animate-pulse rounded" />
                  </div>
                ) : diagnostics?.bouncers && diagnostics.bouncers.length > 0 ? (
                  <div className="space-y-2">
                    {diagnostics.bouncers.map((bouncer, index) => (
                      <div key={index} className="flex items-center justify-between">
                        <span className="text-sm">{bouncer.name}</span>
                        <Badge variant={bouncer.status === 'connected' ? 'default' : 'secondary'}>
                          {bouncer.status}
                        </Badge>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-muted-foreground text-sm">No bouncers connected</p>
                )}
              </CardContent>
            </Card>

            {/* Security Decisions */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-5 w-5" />
                  Security Decisions
                </CardTitle>
              </CardHeader>
              <CardContent>
                {diagnosticsLoading ? (
                  <div className="space-y-2">
                    <div className="h-4 bg-muted animate-pulse rounded" />
                    <div className="h-4 bg-muted animate-pulse rounded" />
                  </div>
                ) : (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Total Decisions</span>
                      <Badge variant="outline">{totalDecisions}</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm">Active Blocks</span>
                      <Badge variant="destructive">
                        {diagnostics?.decisions?.filter(d => d.type === 'ban').length || 0}
                      </Badge>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>

      {/* System Alerts */}
      {!isLoading && overallHealth !== 'success' && (
        <Alert variant={overallHealth === 'error' ? 'destructive' : 'default'}>
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>System Health Alert</AlertTitle>
          <AlertDescription>
            {overallHealth === 'error' 
              ? 'Critical system issues detected. Please check container status and CrowdSec health.'
              : 'Some system components are experiencing issues. Monitor the status dashboard for updates.'
            }
          </AlertDescription>
        </Alert>
      )}
    </div>
  )
}

export default StatusDashboard