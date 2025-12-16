import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Progress } from '@/components/ui/progress'
import { Separator } from '@/components/ui/separator'
import { ProxyType, ProxyHealthData, HealthCheckItem } from '@/lib/proxy-types'
import {
  HeartPulse,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Container,
  Network,
  Activity,
  Clock
} from 'lucide-react'

interface ProxyHealthMonitorProps {
  proxyType: ProxyType
  containerName: string
  healthCheckEnabled: boolean
  className?: string
}

interface HealthMetrics {
  uptime: string
  memoryUsage: number
  cpuUsage: number
  networkConnections: number
  lastHealthCheck: Date
  responseTime: number
}

export function ProxyHealthMonitor({ 
  proxyType, 
  containerName, 
  healthCheckEnabled,
  className 
}: ProxyHealthMonitorProps) {
  const [healthData, setHealthData] = useState<ProxyHealthData | null>(null)
  const [metrics, setMetrics] = useState<HealthMetrics | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date())

  // Mock health data generation
  const generateMockHealthData = (): ProxyHealthData => {
    const checks: HealthCheckItem[] = [
      {
        name: 'Container Status',
        status: Math.random() > 0.1 ? 'healthy' : 'unhealthy',
        message: 'Container is running and responsive',
        details: { containerId: 'abc123', uptime: '2d 14h 32m' }
      },
      {
        name: 'Configuration Valid',
        status: Math.random() > 0.05 ? 'healthy' : 'warning',
        message: 'Configuration files are valid and loaded',
        details: { configPath: `/etc/${proxyType}/config.yml` }
      },
      {
        name: 'Network Connectivity',
        status: Math.random() > 0.02 ? 'healthy' : 'unhealthy',
        message: 'Network interfaces are accessible',
        details: { ports: ['80', '443', '8080'] }
      }
    ]

    if (proxyType === 'traefik') {
      checks.push(
        {
          name: 'Dynamic Configuration',
          status: Math.random() > 0.1 ? 'healthy' : 'warning',
          message: 'Dynamic configuration is loaded and valid',
          details: { providers: ['file', 'docker'] }
        },
        {
          name: 'Middleware Status',
          status: 'healthy',
          message: 'All middleware components are operational',
          details: { middlewares: ['auth', 'ratelimit', 'crowdsec'] }
        }
      )
    }

    if (proxyType === 'nginx') {
      checks.push({
        name: 'Upstream Servers',
        status: Math.random() > 0.15 ? 'healthy' : 'warning',
        message: 'Backend servers are responding',
        details: { upstreams: 3, healthy: 3 }
      })
    }

    const overallStatus = checks.some(c => c.status === 'unhealthy') ? 'unhealthy' :
                         checks.some(c => c.status === 'warning') ? 'warning' : 'healthy'

    return {
      checks,
      overall: overallStatus,
      timestamp: new Date().toISOString()
    }
  }

  const generateMockMetrics = (): HealthMetrics => ({
    uptime: '2d 14h 32m',
    memoryUsage: Math.floor(Math.random() * 40) + 20, // 20-60%
    cpuUsage: Math.floor(Math.random() * 30) + 5,     // 5-35%
    networkConnections: Math.floor(Math.random() * 100) + 50,
    lastHealthCheck: new Date(),
    responseTime: Math.floor(Math.random() * 50) + 10 // 10-60ms
  })

  const refreshHealthData = async () => {
    if (!healthCheckEnabled) return

    setIsLoading(true)
    
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000))
      
      setHealthData(generateMockHealthData())
      setMetrics(generateMockMetrics())
      setLastRefresh(new Date())
    } catch (error) {
      console.error('Failed to fetch health data:', error)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    if (healthCheckEnabled) {
      refreshHealthData()
      
      // Auto-refresh every 30 seconds
      const interval = setInterval(refreshHealthData, 30000)
      return () => clearInterval(interval)
    }
  }, [healthCheckEnabled, proxyType, containerName])

  const getStatusIcon = (status: HealthCheckItem['status']) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'warning':
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />
      case 'unhealthy':
        return <XCircle className="h-4 w-4 text-red-500" />
      default:
        return <AlertTriangle className="h-4 w-4 text-gray-500" />
    }
  }

  const getStatusColor = (status: HealthCheckItem['status']) => {
    switch (status) {
      case 'healthy':
        return 'text-green-600'
      case 'warning':
        return 'text-yellow-600'
      case 'unhealthy':
        return 'text-red-600'
      default:
        return 'text-gray-600'
    }
  }

  const getOverallStatusBadge = (status: ProxyHealthData['overall']) => {
    switch (status) {
      case 'healthy':
        return <Badge className="bg-green-500">Healthy</Badge>
      case 'warning':
        return <Badge variant="secondary" className="bg-yellow-500 text-white">Warning</Badge>
      case 'unhealthy':
        return <Badge variant="destructive">Unhealthy</Badge>
      default:
        return <Badge variant="outline">Unknown</Badge>
    }
  }

  if (!healthCheckEnabled) {
    return (
      <Card className={className}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <HeartPulse className="h-5 w-5" />
            Health Monitoring
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              Health monitoring is disabled. Enable it in the General settings to monitor 
              your {proxyType} container health.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Overall Health Status */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <HeartPulse className="h-5 w-5" />
              Health Status
            </CardTitle>
            <div className="flex items-center gap-2">
              {healthData && getOverallStatusBadge(healthData.overall)}
              <Button 
                variant="outline" 
                size="sm" 
                onClick={refreshHealthData}
                disabled={isLoading}
                className="flex items-center gap-2"
              >
                <RefreshCw className={`h-3 w-3 ${isLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
            </div>
          </div>
          <p className="text-sm text-muted-foreground">
            Last updated: {lastRefresh.toLocaleTimeString()}
          </p>
        </CardHeader>
        <CardContent>
          {isLoading && !healthData ? (
            <div className="flex items-center gap-3 py-8">
              <RefreshCw className="h-4 w-4 animate-spin" />
              <span className="text-sm">Checking health status...</span>
            </div>
          ) : healthData ? (
            <div className="space-y-4">
              {/* Health Checks */}
              <div className="space-y-3">
                {healthData.checks.map((check, index) => (
                  <div key={index} className="flex items-start gap-3">
                    {getStatusIcon(check.status)}
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className={`text-sm font-medium ${getStatusColor(check.status)}`}>
                          {check.name}
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        {check.message}
                      </p>
                      {check.details && (
                        <div className="text-xs text-muted-foreground mt-1 font-mono bg-muted p-2 rounded">
                          {JSON.stringify(check.details, null, 2)}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <Alert>
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                Unable to fetch health data. Check your container configuration.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Performance Metrics */}
      {metrics && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5" />
              Performance Metrics
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span>Memory Usage</span>
                  <span className="font-medium">{metrics.memoryUsage}%</span>
                </div>
                <Progress value={metrics.memoryUsage} className="h-2" />
              </div>
              
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span>CPU Usage</span>
                  <span className="font-medium">{metrics.cpuUsage}%</span>
                </div>
                <Progress value={metrics.cpuUsage} className="h-2" />
              </div>
            </div>

            <Separator />

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
              <div className="space-y-1">
                <div className="flex items-center justify-center gap-1">
                  <Clock className="h-3 w-3 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Uptime</span>
                </div>
                <p className="text-sm font-medium">{metrics.uptime}</p>
              </div>
              
              <div className="space-y-1">
                <div className="flex items-center justify-center gap-1">
                  <Network className="h-3 w-3 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Connections</span>
                </div>
                <p className="text-sm font-medium">{metrics.networkConnections}</p>
              </div>
              
              <div className="space-y-1">
                <div className="flex items-center justify-center gap-1">
                  <Activity className="h-3 w-3 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Response Time</span>
                </div>
                <p className="text-sm font-medium">{metrics.responseTime}ms</p>
              </div>
              
              <div className="space-y-1">
                <div className="flex items-center justify-center gap-1">
                  <Container className="h-3 w-3 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Container</span>
                </div>
                <p className="text-sm font-medium">{containerName}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}