import { ProxyType } from '@/lib/proxy-types'
import { LogStats } from '@/lib/api'
import { LogInsightsDashboard } from './LogInsightsDashboard'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { 
  BarChart3, 
  TrendingUp, 
  Users, 
  Globe, 
  AlertTriangle, 
  RefreshCw,
  Activity,
  Target,
  Clock,
  Hash
} from 'lucide-react'

interface LogAnalyticsDashboardProps {
  logStats: LogStats
  proxyType: ProxyType
  isLoading: boolean
  onRefresh: () => void
}

export function LogAnalyticsDashboard({ 
  logStats, 
  proxyType, 
  isLoading, 
  onRefresh 
}: LogAnalyticsDashboardProps) {
  const proxyName = proxyType.charAt(0).toUpperCase() + proxyType.slice(1)

  const getStatusCodeColor = (code: string) => {
    const codeNum = parseInt(code)
    if (codeNum >= 200 && codeNum < 300) return 'text-green-600'
    if (codeNum >= 300 && codeNum < 400) return 'text-blue-600'
    if (codeNum >= 400 && codeNum < 500) return 'text-yellow-600'
    if (codeNum >= 500) return 'text-red-600'
    return 'text-muted-foreground'
  }



  const getTotalRequests = () => {
    return Object.values(logStats.status_codes).reduce((sum, count) => sum + count, 0)
  }

  const getErrorRate = () => {
    const total = getTotalRequests()
    if (total === 0) return 0
    
    const errors = Object.entries(logStats.status_codes)
      .filter(([code]) => parseInt(code) >= 400)
      .reduce((sum, [, count]) => sum + count, 0)
    
    return (errors / total) * 100
  }

  return (
    <div className="space-y-6">
      {/* Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center gap-2">
              <Hash className="h-4 w-4 text-muted-foreground" />
              <div>
                <p className="text-2xl font-bold">{logStats.total_lines.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">Total Log Lines</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-muted-foreground" />
              <div>
                <p className="text-2xl font-bold">{getTotalRequests().toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">Total Requests</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center gap-2">
              <Users className="h-4 w-4 text-muted-foreground" />
              <div>
                <p className="text-2xl font-bold">{logStats.top_ips.length}</p>
                <p className="text-xs text-muted-foreground">Unique IPs</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
              <div>
                <p className="text-2xl font-bold">{getErrorRate().toFixed(1)}%</p>
                <p className="text-xs text-muted-foreground">Error Rate</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Status Codes Analysis */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <BarChart3 className="h-5 w-5" />
                HTTP Status Codes
              </CardTitle>
              <CardDescription>
                Distribution of HTTP response status codes
              </CardDescription>
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
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(logStats.status_codes)
              .sort(([a], [b]) => parseInt(a) - parseInt(b))
              .map(([code, count]) => (
                <div key={code} className="p-3 border rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className={`font-mono text-sm ${getStatusCodeColor(code)}`}>
                      {code}
                    </span>
                    <span className="text-sm font-medium">{count}</span>
                  </div>
                  <Progress 
                    value={(count / getTotalRequests()) * 100} 
                    className="h-2"
                  />
                  <p className="text-xs text-muted-foreground mt-1">
                    {((count / getTotalRequests()) * 100).toFixed(1)}%
                  </p>
                </div>
              ))}
          </div>
        </CardContent>
      </Card>

      {/* Top IPs */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Target className="h-5 w-5" />
            Top IP Addresses
          </CardTitle>
          <CardDescription>
            Most active IP addresses in the logs
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-64">
            <div className="space-y-2">
              {logStats.top_ips.slice(0, 20).map((ipData, index) => (
                <div key={ipData.ip} className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-center gap-3">
                    <Badge variant="outline" className="text-xs">
                      #{index + 1}
                    </Badge>
                    <span className="font-mono text-sm">{ipData.ip}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{ipData.count} requests</span>
                    <div className="w-20">
                      <Progress 
                        value={(ipData.count / logStats.top_ips[0].count) * 100} 
                        className="h-2"
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
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
            Distribution of HTTP request methods
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(logStats.http_methods)
              .sort(([, a], [, b]) => b - a)
              .map(([method, count]) => (
                <div key={method} className="p-3 border rounded-lg text-center">
                  <p className="font-mono text-lg font-bold">{method}</p>
                  <p className="text-sm text-muted-foreground">{count} requests</p>
                  <Progress 
                    value={(count / getTotalRequests()) * 100} 
                    className="h-2 mt-2"
                  />
                </div>
              ))}
          </div>
        </CardContent>
      </Card>

      {/* Error Entries */}
      {logStats.error_entries.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" />
              Recent Errors
            </CardTitle>
            <CardDescription>
              Recent error entries from the logs
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-48">
              <div className="space-y-2">
                {logStats.error_entries.slice(0, 10).map((entry, index) => (
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
          </CardContent>
        </Card>
      )}

      {/* Analytics Summary */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <TrendingUp className="h-5 w-5" />
            Analytics Summary
          </CardTitle>
          <CardDescription>
            Key insights from {proxyName} access logs
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 border rounded-lg">
              <h4 className="font-medium mb-2">Traffic Health</h4>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Success Rate:</span>
                  <span className="font-medium text-green-600">
                    {(100 - getErrorRate()).toFixed(1)}%
                  </span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>Error Rate:</span>
                  <span className={`font-medium ${getErrorRate() > 5 ? 'text-red-600' : 'text-green-600'}`}>
                    {getErrorRate().toFixed(1)}%
                  </span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>Total Requests:</span>
                  <span className="font-medium">{getTotalRequests().toLocaleString()}</span>
                </div>
              </div>
            </div>

            <div className="p-4 border rounded-lg">
              <h4 className="font-medium mb-2">Top Activity</h4>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Most Active IP:</span>
                  <span className="font-mono text-xs">
                    {logStats.top_ips[0]?.ip || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>Top IP Requests:</span>
                  <span className="font-medium">
                    {logStats.top_ips[0]?.count || 0}
                  </span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>Unique IPs:</span>
                  <span className="font-medium">{logStats.top_ips.length}</span>
                </div>
              </div>
            </div>
          </div>

          {getErrorRate() > 10 && (
            <Alert>
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                High error rate detected ({getErrorRate().toFixed(1)}%). 
                Review error entries and consider investigating potential issues.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Advanced Insights Dashboard */}
      <LogInsightsDashboard
        logStats={logStats}
        proxyType={proxyType}
        isLoading={isLoading}
        onRefresh={onRefresh}
      />
    </div>
  )
}