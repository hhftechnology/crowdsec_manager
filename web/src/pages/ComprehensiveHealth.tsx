
import { useQuery } from '@tanstack/react-query'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { 
  Activity, 
  Shield, 
  Network, 
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Info
} from 'lucide-react'
import api from '@/lib/api'
import { ProxyType } from '@/lib/proxy-types'
import { StatusDashboard } from '@/components/health/StatusDashboard'
import { ProxyHealthIndicator } from '@/components/health/ProxyHealthIndicator'
import { BouncerStatusMonitor } from '@/components/health/BouncerStatusMonitor'
import { useDeployment, useRunningContainers, useContainers, useProxyType } from '@/contexts/DeploymentContext'

export default function ComprehensiveHealth() {
  const { deployment, isLoading: deploymentLoading } = useDeployment()
  const runningContainers = useRunningContainers()
  const allContainers = useContainers()
  const proxyType = useProxyType()

  const { data: proxyInfo, isLoading: proxyLoading } = useQuery({
    queryKey: ['proxy-current'],
    queryFn: async () => {
      const response = await api.proxy.getCurrent()
      return response.data.data
    },
  })

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

  const isLoading = proxyLoading || healthLoading || crowdsecLoading || deploymentLoading

  // Use deployment-aware container counts
  const runningContainerCount = runningContainers.length
  const totalContainerCount = allContainers.length
  const allRunning = runningContainerCount === totalContainerCount && totalContainerCount > 0

  // Calculate overall system health
  const getOverallSystemHealth = () => {
    if (isLoading) return { status: 'loading', message: 'Loading system status...' }
    
    const issues = []
    let status = 'healthy'

    // Check CrowdSec health
    if (crowdsecHealth?.status === 'unhealthy') {
      issues.push('CrowdSec engine is unhealthy')
      status = 'critical'
    } else if (crowdsecHealth?.status === 'degraded') {
      issues.push('CrowdSec engine is degraded')
      if (status !== 'critical') status = 'warning'
    }

    // Check container health
    if (!allRunning) {
      const stoppedContainers = totalContainerCount - runningContainerCount
      issues.push(`${stoppedContainers} container(s) not running`)
      if (status !== 'critical') status = 'warning'
    }

    // Check proxy health
    if (proxyInfo && !proxyInfo.running) {
      issues.push('Proxy container is not running')
      if (status !== 'critical') status = 'warning'
    }

    if (proxyInfo && !proxyInfo.connected) {
      issues.push('Proxy is not responding')
      if (status !== 'critical') status = 'warning'
    }

    const message = issues.length > 0 
      ? issues.join(', ')
      : 'All systems operational'

    return { status, message, issues }
  }

  const systemHealth = getOverallSystemHealth()

  const getHealthIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle2 className="h-5 w-5 text-green-500" />
      case 'warning':
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />
      case 'critical':
        return <XCircle className="h-5 w-5 text-red-500" />
      case 'loading':
        return <Activity className="h-5 w-5 animate-spin text-muted-foreground" />
      default:
        return <Info className="h-5 w-5 text-blue-500" />
    }
  }

  const getHealthBadge = (status: string) => {
    switch (status) {
      case 'healthy':
        return <Badge className="bg-green-500">All Systems Operational</Badge>
      case 'warning':
        return <Badge className="bg-yellow-500">Issues Detected</Badge>
      case 'critical':
        return <Badge variant="destructive">Critical Issues</Badge>
      case 'loading':
        return <Badge variant="outline">Loading...</Badge>
      default:
        return <Badge variant="secondary">Unknown Status</Badge>
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold">Comprehensive Health Monitoring</h1>
        <p className="text-muted-foreground mt-2">
          Complete system health monitoring with real-time updates and diagnostics
        </p>
      </div>

      {/* System Health Alert */}
      <div className="flex items-center justify-between p-4 border rounded-lg">
        <div className="flex items-center gap-3">
          {getHealthIcon(systemHealth.status)}
          <div>
            <p className="font-medium">System Health Status</p>
            <p className="text-sm text-muted-foreground">{systemHealth.message}</p>
          </div>
        </div>
        {getHealthBadge(systemHealth.status)}
      </div>

      {/* Critical Issues Alert */}
      {systemHealth.status === 'critical' && systemHealth.issues && (
        <Alert variant="destructive">
          <XCircle className="h-4 w-4" />
          <AlertTitle>Critical System Issues Detected</AlertTitle>
          <AlertDescription>
            <ul className="list-disc list-inside mt-2 space-y-1">
              {systemHealth.issues.map((issue, index) => (
                <li key={index}>{issue}</li>
              ))}
            </ul>
            <p className="mt-2">
              Please address these issues immediately to ensure system security and functionality.
            </p>
          </AlertDescription>
        </Alert>
      )}

      {/* Warning Issues Alert */}
      {systemHealth.status === 'warning' && systemHealth.issues && (
        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>System Issues Detected</AlertTitle>
          <AlertDescription>
            <ul className="list-disc list-inside mt-2 space-y-1">
              {systemHealth.issues.map((issue, index) => (
                <li key={index}>{issue}</li>
              ))}
            </ul>
            <p className="mt-2">
              Monitor these issues and take corrective action if needed.
            </p>
          </AlertDescription>
        </Alert>
      )}

      {/* Main Content Tabs */}
      <Tabs defaultValue="dashboard" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="dashboard" className="flex items-center gap-2">
            <Activity className="h-4 w-4" />
            Dashboard
          </TabsTrigger>
          <TabsTrigger value="proxy" className="flex items-center gap-2">
            <Network className="h-4 w-4" />
            Proxy Health
          </TabsTrigger>
          <TabsTrigger value="bouncers" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Bouncers
          </TabsTrigger>
          <TabsTrigger value="diagnostics" className="flex items-center gap-2">
            <Info className="h-4 w-4" />
            Diagnostics
          </TabsTrigger>
        </TabsList>

        {/* Status Dashboard Tab */}
        <TabsContent value="dashboard">
          <StatusDashboard />
        </TabsContent>

        {/* Proxy Health Tab */}
        <TabsContent value="proxy">
          {proxyInfo ? (
            <ProxyHealthIndicator proxyType={proxyInfo.type as ProxyType} />
          ) : (
            <div className="text-center py-12">
              <Network className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-muted-foreground">Loading proxy information...</p>
            </div>
          )}
        </TabsContent>

        {/* Bouncer Status Tab */}
        <TabsContent value="bouncers">
          <BouncerStatusMonitor proxyType={proxyInfo?.type as ProxyType} />
        </TabsContent>

        {/* Diagnostics Tab */}
        <TabsContent value="diagnostics">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* System Information */}
            <div className="space-y-4">
              <h3 className="text-lg font-semibold">System Information</h3>
              
              {proxyInfo && (
                <div className="p-4 border rounded-lg space-y-3">
                  <h4 className="font-medium">Proxy Configuration</h4>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Type:</span>
                      <span className="font-medium capitalize">{proxyInfo.type}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Container:</span>
                      <span className="font-mono">{proxyInfo.container_name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Status:</span>
                      <Badge variant={proxyInfo.running ? 'default' : 'destructive'}>
                        {proxyInfo.running ? 'Running' : 'Stopped'}
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Connection:</span>
                      <Badge variant={proxyInfo.connected ? 'default' : 'secondary'}>
                        {proxyInfo.connected ? 'Connected' : 'Disconnected'}
                      </Badge>
                    </div>
                  </div>
                </div>
              )}

              {healthData && (
                <div className="p-4 border rounded-lg space-y-3">
                  <h4 className="font-medium">Deployment Container Status</h4>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Total Containers:</span>
                      <span className="font-medium">{totalContainerCount}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Running:</span>
                      <span className="font-medium text-green-600">{runningContainerCount}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Stopped:</span>
                      <span className="font-medium text-red-600">{totalContainerCount - runningContainerCount}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Last Check:</span>
                      <span className="font-medium">
                        {deployment?.detectedAt ? new Date(deployment.detectedAt).toLocaleTimeString() : 'Never'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Deployment Type:</span>
                      <span className="font-medium capitalize">{proxyType || 'Unknown'}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Health Checks */}
            <div className="space-y-4">
              <h3 className="text-lg font-semibold">Health Checks</h3>
              
              {crowdsecHealth && (
                <div className="p-4 border rounded-lg space-y-3">
                  <h4 className="font-medium">CrowdSec Engine</h4>
                  <div className="space-y-2">
                    {Object.entries(crowdsecHealth.checks || {}).map(([checkName, check]: [string, any]) => (
                      <div key={checkName} className="flex items-center justify-between">
                        <span className="text-sm capitalize">{checkName.replace('_', ' ')}</span>
                        <div className="flex items-center gap-2">
                          {check.status === 'healthy' ? (
                            <CheckCircle2 className="h-4 w-4 text-green-500" />
                          ) : check.status === 'unhealthy' ? (
                            <XCircle className="h-4 w-4 text-red-500" />
                          ) : (
                            <AlertTriangle className="h-4 w-4 text-yellow-500" />
                          )}
                          <Badge 
                            variant={check.status === 'healthy' ? 'default' : 'destructive'}
                            className="text-xs"
                          >
                            {check.status}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Quick Actions */}
              <div className="p-4 border rounded-lg space-y-3">
                <h4 className="font-medium">Quick Actions</h4>
                <div className="grid grid-cols-2 gap-2">
                  <button 
                    className="p-2 text-sm border rounded hover:bg-muted transition-colors"
                    onClick={() => window.location.reload()}
                  >
                    Refresh All
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
                    CrowdSec Details
                  </button>
                  <button 
                    className="p-2 text-sm border rounded hover:bg-muted transition-colors"
                    onClick={() => window.open('/logs', '_blank')}
                  >
                    System Logs
                  </button>
                </div>
              </div>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}