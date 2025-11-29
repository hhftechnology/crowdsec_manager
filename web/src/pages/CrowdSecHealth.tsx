import { useQuery } from '@tanstack/react-query'
import api from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
  Activity,
  Shield,
  Database,
  BarChart3,
  Cloud,
  Container
} from 'lucide-react'

interface HealthCheckItem {
  status: string
  message: string
  error?: string
  details?: string
  metrics?: Record<string, any>
}

interface CrowdSecHealthData {
  status: string
  timestamp: string
  checks: {
    container?: HealthCheckItem
    lapi?: HealthCheckItem
    metrics?: HealthCheckItem
    bouncers?: HealthCheckItem
    console?: HealthCheckItem
  }
}

export default function CrowdSecHealth() {
  const { data: healthData, isLoading, error } = useQuery({
    queryKey: ['crowdsec-health'],
    queryFn: async () => {
      const response = await api.health.crowdsecHealth()
      return response.data.data as CrowdSecHealthData
    },
    refetchInterval: 5000, // Refresh every 5 seconds
  })

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle2 className="h-5 w-5 text-green-500" />
      case 'unhealthy':
        return <XCircle className="h-5 w-5 text-red-500" />
      case 'degraded':
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />
      case 'warning':
        return <AlertTriangle className="h-5 w-5 text-orange-500" />
      case 'info':
        return <Info className="h-5 w-5 text-blue-500" />
      default:
        return <Activity className="h-5 w-5 text-muted-foreground" />
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

  const getCheckIcon = (checkName: string) => {
    switch (checkName) {
      case 'container':
        return <Container className="h-5 w-5" />
      case 'lapi':
        return <Database className="h-5 w-5" />
      case 'metrics':
        return <BarChart3 className="h-5 w-5" />
      case 'bouncers':
        return <Shield className="h-5 w-5" />
      case 'console':
        return <Cloud className="h-5 w-5" />
      default:
        return <Activity className="h-5 w-5" />
    }
  }

  const getCheckTitle = (checkName: string) => {
    switch (checkName) {
      case 'container':
        return 'Container Status'
      case 'lapi':
        return 'Local API (LAPI)'
      case 'metrics':
        return 'Metrics Endpoint'
      case 'bouncers':
        return 'Bouncers'
      case 'console':
        return 'CrowdSec Console'
      default:
        return checkName
    }
  }

  if (error) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">CrowdSec Security Engine Health</h1>
          <p className="text-muted-foreground mt-2">
            Real-time health monitoring of CrowdSec Security Engine
          </p>
        </div>
        <Alert variant="destructive">
          <XCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>
            Failed to fetch health status. Please ensure the CrowdSec container is running.
          </AlertDescription>
        </Alert>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">CrowdSec Security Engine Health</h1>
        <p className="text-muted-foreground mt-2">
          Real-time health monitoring of CrowdSec Security Engine
        </p>
      </div>

      {/* Overall Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {isLoading ? (
              <Activity className="h-5 w-5 animate-pulse" />
            ) : (
              getStatusIcon(healthData?.status || 'unknown')
            )}
            Overall Health Status
          </CardTitle>
          <CardDescription>
            Last checked: {healthData?.timestamp ? new Date(healthData.timestamp).toLocaleString() : 'Never'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center p-8">
              <Activity className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div>
                <p className="text-sm font-medium">System Status</p>
                <p className="text-2xl font-bold capitalize">{healthData?.status || 'Unknown'}</p>
              </div>
              {getStatusBadge(healthData?.status || 'unknown')}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Detailed Health Checks */}
      {healthData?.checks && (
        <div className="grid gap-4 md:grid-cols-2">
          {Object.entries(healthData.checks).map(([checkName, check]) => (
            <Card key={checkName}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  {getCheckIcon(checkName)}
                  {getCheckTitle(checkName)}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {getStatusIcon(check.status)}
                    <span className="font-medium">{check.message}</span>
                  </div>
                  {getStatusBadge(check.status)}
                </div>

                {check.error && (
                  <Alert variant="destructive">
                    <AlertDescription className="text-sm">
                      <strong>Error:</strong> {check.error}
                    </AlertDescription>
                  </Alert>
                )}

                {checkName === 'metrics' && check.metrics ? (
                  <div className="space-y-4 mt-4">
                    {Object.entries(check.metrics).map(([category, metrics]) => (
                      <div key={category} className="border rounded-md p-3 bg-card">
                        <h4 className="font-semibold text-sm mb-2 capitalize border-b pb-1">
                          {category.replace(/_/g, ' ')}
                        </h4>
                        <div className="grid grid-cols-1 gap-2">
                          {Object.entries(metrics as Record<string, any>).map(([key, value]) => (
                            <div key={key} className="flex flex-col text-sm border-b last:border-0 pb-2 last:pb-0">
                              <span className="text-muted-foreground font-medium mb-1 truncate" title={key}>
                                {key}
                              </span>
                              <div className="pl-2">
                                {typeof value === 'object' && value !== null ? (
                                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-4 gap-y-1">
                                    {Object.entries(value).map(([subKey, subValue]) => (
                                      <div key={subKey} className="flex items-center gap-1">
                                        <span className="text-xs text-muted-foreground">{subKey}:</span>
                                        <span className="font-mono font-medium text-xs">
                                          {String(subValue)}
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <span className="font-mono font-medium">{String(value)}</span>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  check.details && (
                    <div className="p-3 bg-muted rounded-md overflow-x-auto">
                      <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap">
                        {check.details}
                      </pre>
                    </div>
                  )
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Status Legend */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Status Legend</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-5">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-green-500" />
              <span className="text-sm">Healthy - All checks passed</span>
            </div>
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-yellow-500" />
              <span className="text-sm">Degraded - Some issues detected</span>
            </div>
            <div className="flex items-center gap-2">
              <XCircle className="h-4 w-4 text-red-500" />
              <span className="text-sm">Unhealthy - Critical failure</span>
            </div>
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-500" />
              <span className="text-sm">Warning - Needs attention</span>
            </div>
            <div className="flex items-center gap-2">
              <Info className="h-4 w-4 text-blue-500" />
              <span className="text-sm">Info - Informational</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
