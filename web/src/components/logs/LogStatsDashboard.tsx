import { useMemo } from 'react'
import { ProxyType } from '@/lib/proxy-types'
import { LogStats } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { 
  BarChart3, 
  TrendingUp, 
  TrendingDown,
  Users, 
  Globe, 
  AlertTriangle, 
  RefreshCw,
  Activity,
  Target,
  Hash,
  Shield,
  Zap,
  Eye,
  Server
} from 'lucide-react'

interface LogStatsDashboardProps {
  logStats: LogStats
  proxyType: ProxyType
  isLoading: boolean
  onRefresh: () => void
  timeRange?: string
}

interface StatCard {
  title: string
  value: string | number
  icon: React.ComponentType<{ className?: string }>
  trend?: 'up' | 'down' | 'stable'
  trendValue?: string
  description?: string
  variant?: 'default' | 'success' | 'warning' | 'error'
}

export function LogStatsDashboard({ 
  logStats, 
  proxyType, 
  isLoading, 
  onRefresh,
  timeRange = 'all'
}: LogStatsDashboardProps) {
  const proxyName = proxyType.charAt(0).toUpperCase() + proxyType.slice(1)

  // Calculate comprehensive statistics
  const stats = useMemo(() => {
    if (!logStats) return null

    const totalRequests = Object.values(logStats.status_codes).reduce((sum, count) => sum + count, 0)
    const errorRequests = Object.entries(logStats.status_codes)
      .filter(([code]) => parseInt(code) >= 400)
      .reduce((sum, [, count]) => sum + count, 0)
    
    const successRequests = Object.entries(logStats.status_codes)
      .filter(([code]) => parseInt(code) >= 200 && parseInt(code) < 300)
      .reduce((sum, [, count]) => sum + count, 0)

    const redirectRequests = Object.entries(logStats.status_codes)
      .filter(([code]) => parseInt(code) >= 300 && parseInt(code) < 400)
      .reduce((sum, [, count]) => sum + count, 0)

    const serverErrorRequests = Object.entries(logStats.status_codes)
      .filter(([code]) => parseInt(code) >= 500)
      .reduce((sum, [, count]) => sum + count, 0)

    const clientErrorRequests = Object.entries(logStats.status_codes)
      .filter(([code]) => parseInt(code) >= 400 && parseInt(code) < 500)
      .reduce((sum, [, count]) => sum + count, 0)

    const errorRate = totalRequests > 0 ? (errorRequests / totalRequests) * 100 : 0
    const successRate = totalRequests > 0 ? (successRequests / totalRequests) * 100 : 0

    // Top IP analysis
    const topIP = logStats.top_ips[0]
    const topIPPercentage = totalRequests > 0 && topIP ? (topIP.count / totalRequests) * 100 : 0

    // HTTP methods analysis
    const topMethod = Object.entries(logStats.http_methods)
      .sort(([, a], [, b]) => b - a)[0]

    return {
      totalRequests,
      errorRequests,
      successRequests,
      redirectRequests,
      serverErrorRequests,
      clientErrorRequests,
      errorRate,
      successRate,
      uniqueIPs: logStats.top_ips.length,
      totalLogLines: logStats.total_lines,
      errorEntries: logStats.error_entries.length,
      topIP,
      topIPPercentage,
      topMethod: topMethod ? { method: topMethod[0], count: topMethod[1] } : null,
      avgRequestsPerIP: logStats.top_ips.length > 0 ? Math.round(totalRequests / logStats.top_ips.length) : 0
    }
  }, [logStats])

  if (!stats) return null

  // Generate stat cards based on proxy type and available data
  const statCards: StatCard[] = [
    {
      title: 'Total Requests',
      value: stats.totalRequests.toLocaleString(),
      icon: Activity,
      description: 'HTTP requests processed',
      variant: 'default'
    },
    {
      title: 'Success Rate',
      value: `${stats.successRate.toFixed(1)}%`,
      icon: Shield,
      trend: stats.successRate > 95 ? 'up' : stats.successRate < 80 ? 'down' : 'stable',
      description: '2xx responses',
      variant: stats.successRate > 90 ? 'success' : stats.successRate > 70 ? 'warning' : 'error'
    },
    {
      title: 'Error Rate',
      value: `${stats.errorRate.toFixed(1)}%`,
      icon: AlertTriangle,
      trend: stats.errorRate > 10 ? 'up' : stats.errorRate < 2 ? 'down' : 'stable',
      description: '4xx & 5xx responses',
      variant: stats.errorRate < 5 ? 'success' : stats.errorRate < 15 ? 'warning' : 'error'
    },
    {
      title: 'Unique Visitors',
      value: stats.uniqueIPs.toLocaleString(),
      icon: Users,
      description: 'Distinct IP addresses',
      variant: 'default'
    }
  ]

  // Add proxy-specific stats
  if (proxyType !== 'standalone') {
    statCards.push(
      {
        title: 'Top IP Traffic',
        value: `${stats.topIPPercentage.toFixed(1)}%`,
        icon: Target,
        trend: stats.topIPPercentage > 50 ? 'up' : 'stable',
        description: stats.topIP ? `${stats.topIP.ip}` : 'N/A',
        variant: stats.topIPPercentage > 50 ? 'warning' : 'default'
      },
      {
        title: 'Avg Requests/IP',
        value: stats.avgRequestsPerIP.toLocaleString(),
        icon: BarChart3,
        description: 'Average per visitor',
        variant: 'default'
      }
    )
  }

  // Add log-specific stats
  statCards.push(
    {
      title: 'Log Entries',
      value: stats.totalLogLines.toLocaleString(),
      icon: Hash,
      description: 'Total log lines',
      variant: 'default'
    },
    {
      title: 'Error Entries',
      value: stats.errorEntries.toLocaleString(),
      icon: Zap,
      description: 'Error log entries',
      variant: stats.errorEntries > 10 ? 'warning' : 'success'
    }
  )

  const getCardVariantClass = (variant: StatCard['variant']) => {
    switch (variant) {
      case 'success':
        return 'border-green-200 bg-green-50'
      case 'warning':
        return 'border-yellow-200 bg-yellow-50'
      case 'error':
        return 'border-red-200 bg-red-50'
      default:
        return ''
    }
  }

  const getTrendIcon = (trend?: StatCard['trend']) => {
    switch (trend) {
      case 'up':
        return <TrendingUp className="h-3 w-3 text-green-500" />
      case 'down':
        return <TrendingDown className="h-3 w-3 text-red-500" />
      default:
        return <Activity className="h-3 w-3 text-muted-foreground" />
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Log Statistics</h2>
          <p className="text-muted-foreground">
            Comprehensive analytics for {proxyName} logs
            {timeRange !== 'all' && ` (${timeRange})`}
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={onRefresh}
          disabled={isLoading}
        >
          <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Stat Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((card, index) => (
          <Card key={index} className={getCardVariantClass(card.variant)}>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <card.icon className="h-5 w-5 text-muted-foreground" />
                  <div>
                    <p className="text-2xl font-bold">{card.value}</p>
                    <p className="text-xs text-muted-foreground">{card.title}</p>
                  </div>
                </div>
                {card.trend && (
                  <div className="flex items-center gap-1">
                    {getTrendIcon(card.trend)}
                    {card.trendValue && (
                      <span className="text-xs text-muted-foreground">
                        {card.trendValue}
                      </span>
                    )}
                  </div>
                )}
              </div>
              {card.description && (
                <p className="text-xs text-muted-foreground mt-2">
                  {card.description}
                </p>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Detailed Breakdowns */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Status Code Distribution */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5" />
              Status Code Distribution
            </CardTitle>
            <CardDescription>
              HTTP response status breakdown
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {Object.entries(logStats.status_codes)
                .sort(([a], [b]) => parseInt(a) - parseInt(b))
                .map(([code, count]) => {
                  const percentage = stats.totalRequests > 0 ? (count / stats.totalRequests) * 100 : 0
                  const codeNum = parseInt(code)
                  const category = codeNum >= 500 ? 'Server Error' 
                                 : codeNum >= 400 ? 'Client Error'
                                 : codeNum >= 300 ? 'Redirect'
                                 : codeNum >= 200 ? 'Success'
                                 : 'Other'
                  
                  const variant = codeNum >= 500 ? 'destructive'
                                : codeNum >= 400 ? 'secondary'
                                : codeNum >= 300 ? 'outline'
                                : 'default'

                  return (
                    <div key={code} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge variant={variant} className="font-mono text-xs">
                          {code}
                        </Badge>
                        <span className="text-sm">{category}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">{count}</span>
                        <div className="w-16">
                          <Progress value={percentage} className="h-2" />
                        </div>
                        <span className="text-xs text-muted-foreground w-12">
                          {percentage.toFixed(1)}%
                        </span>
                      </div>
                    </div>
                  )
                })}
            </div>
          </CardContent>
        </Card>

        {/* HTTP Methods */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5" />
              HTTP Methods
            </CardTitle>
            <CardDescription>
              Request method distribution
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {Object.entries(logStats.http_methods)
                .sort(([, a], [, b]) => b - a)
                .map(([method, count]) => {
                  const percentage = stats.totalRequests > 0 ? (count / stats.totalRequests) * 100 : 0
                  
                  return (
                    <div key={method} className="flex items-center justify-between">
                      <Badge variant="outline" className="font-mono">
                        {method}
                      </Badge>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">{count}</span>
                        <div className="w-16">
                          <Progress value={percentage} className="h-2" />
                        </div>
                        <span className="text-xs text-muted-foreground w-12">
                          {percentage.toFixed(1)}%
                        </span>
                      </div>
                    </div>
                  )
                })}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Top IPs */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Target className="h-5 w-5" />
            Top IP Addresses
          </CardTitle>
          <CardDescription>
            Most active IP addresses ({logStats.top_ips.length} unique)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-64">
            <div className="space-y-2">
              {logStats.top_ips.slice(0, 20).map((ipData, index) => {
                const percentage = stats.totalRequests > 0 ? (ipData.count / stats.totalRequests) * 100 : 0
                const isHighTraffic = percentage > 20
                
                return (
                  <div key={ipData.ip} className={`flex items-center justify-between p-3 border rounded-lg ${
                    isHighTraffic ? 'bg-yellow-50 border-yellow-200' : ''
                  }`}>
                    <div className="flex items-center gap-3">
                      <Badge variant="outline" className="text-xs">
                        #{index + 1}
                      </Badge>
                      <span className="font-mono text-sm">{ipData.ip}</span>
                      {isHighTraffic && (
                        <Badge variant="secondary" className="text-xs">
                          High Traffic
                        </Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{ipData.count} requests</span>
                      <div className="w-20">
                        <Progress 
                          value={(ipData.count / logStats.top_ips[0].count) * 100} 
                          className="h-2"
                        />
                      </div>
                      <span className="text-xs text-muted-foreground">
                        ({percentage.toFixed(1)}%)
                      </span>
                    </div>
                  </div>
                )
              })}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Health Summary */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Eye className="h-5 w-5" />
            Health Summary
          </CardTitle>
          <CardDescription>
            Overall system health indicators
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 border rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="h-4 w-4 text-green-500" />
                <span className="font-medium">Traffic Health</span>
              </div>
              <div className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <span>Success Rate:</span>
                  <span className={stats.successRate > 90 ? 'text-green-600' : 'text-yellow-600'}>
                    {stats.successRate.toFixed(1)}%
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Error Rate:</span>
                  <span className={stats.errorRate < 5 ? 'text-green-600' : 'text-red-600'}>
                    {stats.errorRate.toFixed(1)}%
                  </span>
                </div>
              </div>
            </div>

            <div className="p-4 border rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Server className="h-4 w-4 text-blue-500" />
                <span className="font-medium">Load Distribution</span>
              </div>
              <div className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <span>Unique IPs:</span>
                  <span>{stats.uniqueIPs}</span>
                </div>
                <div className="flex justify-between">
                  <span>Avg/IP:</span>
                  <span>{stats.avgRequestsPerIP}</span>
                </div>
              </div>
            </div>

            <div className="p-4 border rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Activity className="h-4 w-4 text-purple-500" />
                <span className="font-medium">Log Quality</span>
              </div>
              <div className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <span>Total Lines:</span>
                  <span>{stats.totalLogLines.toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span>Error Entries:</span>
                  <span className={stats.errorEntries > 10 ? 'text-yellow-600' : 'text-green-600'}>
                    {stats.errorEntries}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Alerts */}
          {(stats.errorRate > 15 || stats.topIPPercentage > 60 || stats.errorEntries > 50) && (
            <Alert className="mt-4">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                <div className="space-y-1">
                  <p className="font-medium">Attention Required:</p>
                  {stats.errorRate > 15 && (
                    <p>• High error rate ({stats.errorRate.toFixed(1)}%) - investigate failing requests</p>
                  )}
                  {stats.topIPPercentage > 60 && (
                    <p>• Traffic concentration ({stats.topIPPercentage.toFixed(1)}% from {stats.topIP?.ip}) - potential bot activity</p>
                  )}
                  {stats.errorEntries > 50 && (
                    <p>• Many error log entries ({stats.errorEntries}) - check system health</p>
                  )}
                </div>
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
    </div>
  )
}