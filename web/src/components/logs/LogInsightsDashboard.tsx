import { useMemo } from 'react'
import { ProxyType } from '@/lib/proxy-types'
import { LogStats } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { 
  TrendingUp, 
  TrendingDown, 
  AlertTriangle, 
  RefreshCw,
  Activity,
  Target,
  Clock,
  BarChart3,
  PieChart,
  LineChart,
  Info,
  CheckCircle,
  XCircle
} from 'lucide-react'

interface LogInsightsDashboardProps {
  logStats: LogStats
  proxyType: ProxyType
  isLoading: boolean
  onRefresh: () => void
}

interface TrafficInsight {
  type: 'success' | 'warning' | 'error' | 'info'
  title: string
  description: string
  value?: string | number
  trend?: 'up' | 'down' | 'stable'
}

export function LogInsightsDashboard({ 
  logStats, 
  proxyType, 
  isLoading, 
  onRefresh 
}: LogInsightsDashboardProps) {
  const proxyName = proxyType.charAt(0).toUpperCase() + proxyType.slice(1)

  // Calculate insights from log stats
  const insights = useMemo((): TrafficInsight[] => {
    if (!logStats) return []

    const totalRequests = Object.values(logStats.status_codes).reduce((sum, count) => sum + count, 0)
    const errorRequests = Object.entries(logStats.status_codes)
      .filter(([code]) => parseInt(code) >= 400)
      .reduce((sum, [, count]) => sum + count, 0)
    
    const successRequests = Object.entries(logStats.status_codes)
      .filter(([code]) => parseInt(code) >= 200 && parseInt(code) < 300)
      .reduce((sum, [, count]) => sum + count, 0)

    const errorRate = totalRequests > 0 ? (errorRequests / totalRequests) * 100 : 0
    const successRate = totalRequests > 0 ? (successRequests / totalRequests) * 100 : 0

    const insights: TrafficInsight[] = []

    // Traffic Volume Insight
    insights.push({
      type: totalRequests > 1000 ? 'info' : totalRequests > 100 ? 'success' : 'warning',
      title: 'Traffic Volume',
      description: `${totalRequests.toLocaleString()} total requests processed`,
      value: totalRequests,
      trend: totalRequests > 500 ? 'up' : totalRequests > 100 ? 'stable' : 'down'
    })

    // Error Rate Insight
    insights.push({
      type: errorRate > 10 ? 'error' : errorRate > 5 ? 'warning' : 'success',
      title: 'Error Rate',
      description: `${errorRate.toFixed(1)}% of requests resulted in errors`,
      value: `${errorRate.toFixed(1)}%`,
      trend: errorRate > 10 ? 'up' : errorRate < 2 ? 'down' : 'stable'
    })

    // Success Rate Insight
    insights.push({
      type: successRate > 90 ? 'success' : successRate > 70 ? 'warning' : 'error',
      title: 'Success Rate',
      description: `${successRate.toFixed(1)}% of requests were successful`,
      value: `${successRate.toFixed(1)}%`,
      trend: successRate > 90 ? 'up' : successRate < 70 ? 'down' : 'stable'
    })

    // Unique Visitors Insight
    insights.push({
      type: logStats.top_ips.length > 50 ? 'info' : logStats.top_ips.length > 10 ? 'success' : 'warning',
      title: 'Unique Visitors',
      description: `${logStats.top_ips.length} unique IP addresses detected`,
      value: logStats.top_ips.length,
      trend: logStats.top_ips.length > 20 ? 'up' : 'stable'
    })

    // Security Concerns
    if (logStats.error_entries.length > 0) {
      insights.push({
        type: 'warning',
        title: 'Security Events',
        description: `${logStats.error_entries.length} error entries require attention`,
        value: logStats.error_entries.length,
        trend: 'up'
      })
    }

    // Top IP Analysis
    if (logStats.top_ips.length > 0) {
      const topIP = logStats.top_ips[0]
      const topIPPercentage = totalRequests > 0 ? (topIP.count / totalRequests) * 100 : 0
      
      if (topIPPercentage > 50) {
        insights.push({
          type: 'warning',
          title: 'Traffic Concentration',
          description: `Top IP (${topIP.ip}) accounts for ${topIPPercentage.toFixed(1)}% of traffic`,
          value: `${topIPPercentage.toFixed(1)}%`,
          trend: 'up'
        })
      }
    }

    return insights
  }, [logStats])

  const getInsightIcon = (type: TrafficInsight['type']) => {
    switch (type) {
      case 'success':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'warning':
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />
      case 'error':
        return <XCircle className="h-4 w-4 text-red-500" />
      default:
        return <Info className="h-4 w-4 text-blue-500" />
    }
  }

  const getTrendIcon = (trend?: TrafficInsight['trend']) => {
    switch (trend) {
      case 'up':
        return <TrendingUp className="h-3 w-3 text-green-500" />
      case 'down':
        return <TrendingDown className="h-3 w-3 text-red-500" />
      default:
        return <Activity className="h-3 w-3 text-muted-foreground" />
    }
  }

  const getTopMethods = () => {
    if (!logStats.http_methods) return []
    
    return Object.entries(logStats.http_methods)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5)
  }

  const getStatusCodeDistribution = () => {
    if (!logStats.status_codes) return []
    
    const total = Object.values(logStats.status_codes).reduce((sum, count) => sum + count, 0)
    
    return Object.entries(logStats.status_codes)
      .map(([code, count]) => ({
        code,
        count,
        percentage: total > 0 ? (count / total) * 100 : 0,
        category: parseInt(code) >= 500 ? 'Server Error' 
                : parseInt(code) >= 400 ? 'Client Error'
                : parseInt(code) >= 300 ? 'Redirect'
                : parseInt(code) >= 200 ? 'Success'
                : 'Other'
      }))
      .sort((a, b) => b.count - a.count)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Log Insights</h2>
          <p className="text-muted-foreground">
            Advanced analytics and insights from {proxyName} access logs
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

      {/* Key Insights */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <TrendingUp className="h-5 w-5" />
            Key Insights
          </CardTitle>
          <CardDescription>
            Automated analysis of traffic patterns and potential issues
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {insights.map((insight, index) => (
              <div key={index} className="p-4 border rounded-lg">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {getInsightIcon(insight.type)}
                    <span className="font-medium text-sm">{insight.title}</span>
                  </div>
                  {insight.trend && getTrendIcon(insight.trend)}
                </div>
                <p className="text-sm text-muted-foreground mb-2">
                  {insight.description}
                </p>
                {insight.value && (
                  <div className="text-lg font-bold">
                    {insight.value}
                  </div>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Detailed Analytics */}
      <Tabs defaultValue="traffic" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="traffic">Traffic Analysis</TabsTrigger>
          <TabsTrigger value="errors">Error Analysis</TabsTrigger>
          <TabsTrigger value="security">Security Insights</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
        </TabsList>

        <TabsContent value="traffic" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Status Code Distribution */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <PieChart className="h-5 w-5" />
                  Status Code Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {getStatusCodeDistribution().map(({ code, count, percentage, category }) => (
                    <div key={code} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge 
                          variant={
                            category === 'Success' ? 'default' :
                            category === 'Client Error' ? 'secondary' :
                            category === 'Server Error' ? 'destructive' : 'outline'
                          }
                          className="font-mono text-xs"
                        >
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
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* HTTP Methods */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <BarChart3 className="h-5 w-5" />
                  HTTP Methods
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {getTopMethods().map(([method, count]) => {
                    const total = Object.values(logStats.http_methods).reduce((sum, c) => sum + c, 0)
                    const percentage = total > 0 ? (count / total) * 100 : 0
                    
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
        </TabsContent>

        <TabsContent value="errors" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5" />
                Error Analysis
              </CardTitle>
              <CardDescription>
                Detailed analysis of error patterns and trends
              </CardDescription>
            </CardHeader>
            <CardContent>
              {logStats.error_entries.length > 0 ? (
                <ScrollArea className="h-64">
                  <div className="space-y-2">
                    {logStats.error_entries.slice(0, 20).map((entry, index) => (
                      <div key={index} className="p-3 border rounded-lg bg-red-50 border-red-200">
                        <div className="flex items-start justify-between">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <Badge variant="destructive" className="text-xs">
                                {entry.level}
                              </Badge>
                              <span className="text-xs text-muted-foreground">
                                {entry.service}
                              </span>
                            </div>
                            <p className="text-sm font-mono break-all">{entry.message}</p>
                          </div>
                          <div className="flex items-center gap-1 text-xs text-muted-foreground ml-2">
                            <Clock className="h-3 w-3" />
                            <span>{new Date(entry.timestamp).toLocaleTimeString()}</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              ) : (
                <div className="text-center py-8">
                  <CheckCircle className="h-12 w-12 mx-auto text-green-500 mb-4" />
                  <h3 className="text-lg font-medium mb-2">No Errors Detected</h3>
                  <p className="text-muted-foreground">
                    All requests completed successfully without errors.
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Target className="h-5 w-5" />
                Security Insights
              </CardTitle>
              <CardDescription>
                Analysis of potential security threats and patterns
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {/* Top IPs Analysis */}
                <div>
                  <h4 className="font-medium mb-3">Top Traffic Sources</h4>
                  <div className="space-y-2">
                    {logStats.top_ips.slice(0, 10).map((ipData, index) => {
                      const total = Object.values(logStats.status_codes).reduce((sum, count) => sum + count, 0)
                      const percentage = total > 0 ? (ipData.count / total) * 100 : 0
                      const isHighTraffic = percentage > 20
                      
                      return (
                        <div key={ipData.ip} className={`p-3 border rounded-lg ${isHighTraffic ? 'bg-yellow-50 border-yellow-200' : ''}`}>
                          <div className="flex items-center justify-between">
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
                              <span className="text-xs text-muted-foreground">
                                ({percentage.toFixed(1)}%)
                              </span>
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>

                {/* Security Recommendations */}
                <Alert>
                  <Info className="h-4 w-4" />
                  <AlertDescription>
                    <div className="space-y-2">
                      <p className="font-medium">Security Recommendations:</p>
                      <ul className="list-disc list-inside space-y-1 text-sm">
                        <li>Monitor IPs with unusually high traffic patterns</li>
                        <li>Review error logs for potential attack patterns</li>
                        <li>Consider implementing rate limiting for high-traffic sources</li>
                        <li>Enable CrowdSec scenarios for automated threat detection</li>
                      </ul>
                    </div>
                  </AlertDescription>
                </Alert>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="performance" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <LineChart className="h-5 w-5" />
                Performance Metrics
              </CardTitle>
              <CardDescription>
                Performance analysis and optimization recommendations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {/* Performance Summary */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-4 border rounded-lg text-center">
                    <p className="text-sm text-muted-foreground">Total Requests</p>
                    <p className="text-2xl font-bold">{logStats.total_lines.toLocaleString()}</p>
                  </div>
                  <div className="p-4 border rounded-lg text-center">
                    <p className="text-sm text-muted-foreground">Unique Clients</p>
                    <p className="text-2xl font-bold">{logStats.top_ips.length}</p>
                  </div>
                  <div className="p-4 border rounded-lg text-center">
                    <p className="text-sm text-muted-foreground">Avg Requests/IP</p>
                    <p className="text-2xl font-bold">
                      {logStats.top_ips.length > 0 
                        ? Math.round(logStats.total_lines / logStats.top_ips.length)
                        : 0
                      }
                    </p>
                  </div>
                </div>

                {/* Performance Insights */}
                <Alert>
                  <Activity className="h-4 w-4" />
                  <AlertDescription>
                    <div className="space-y-2">
                      <p className="font-medium">Performance Insights:</p>
                      <ul className="list-disc list-inside space-y-1 text-sm">
                        <li>Monitor response times for performance bottlenecks</li>
                        <li>Implement caching for frequently requested resources</li>
                        <li>Consider load balancing for high-traffic applications</li>
                        <li>Review error rates to identify problematic endpoints</li>
                      </ul>
                    </div>
                  </AlertDescription>
                </Alert>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}