import { useState, useEffect, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import api from '@/lib/api'
import { ProxyType } from '@/lib/proxy-types'
import { useProxy, useProxyCapabilities } from '@/contexts/ProxyContext'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Label } from '@/components/ui/label'
import { 
  Activity, 
  BarChart3, 
  RefreshCw, 
  Filter,
  Info,
  Network,
  TrendingUp,
  Eye,
  Settings
} from 'lucide-react'
import { FeatureAvailabilityIndicator } from '../whitelist/FeatureAvailabilityIndicator'
import { LogViewer } from './LogViewer'
import { LogAnalyticsDashboard } from './LogAnalyticsDashboard'
import { LogInsightsDashboard } from './LogInsightsDashboard'
import { LogParsingStatus } from './LogParsingStatus'
import { LogFilterPanel, LogFilter } from './LogFilterPanel'
import { LogStatsDashboard } from './LogStatsDashboard'

interface AdaptiveLogManagerProps {
  // Props are now optional since we get them from context
  proxyType?: ProxyType
}

export function AdaptiveLogManager({ 
  proxyType: propProxyType
}: AdaptiveLogManagerProps = {}) {
  // Use proxy context for adaptive behavior
  const { proxyType: contextProxyType } = useProxy()
  const { supportsLogs, proxyName } = useProxyCapabilities()
  
  // Use props if provided, otherwise use context
  const proxyType = propProxyType || contextProxyType
  // Initialize state from localStorage or defaults
  const [selectedLogType, setSelectedLogType] = useState<'crowdsec' | 'proxy'>(() => {
    return localStorage.getItem('logManager_selectedLogType') as 'crowdsec' | 'proxy' || 'crowdsec'
  })
  const [tailLines, setTailLines] = useState(() => {
    return localStorage.getItem('logManager_tailLines') || '100'
  })
  const [autoRefresh, setAutoRefresh] = useState(() => {
    return localStorage.getItem('logManager_autoRefresh') === 'true'
  })
  const [logFilters, setLogFilters] = useState<LogFilter>({
    searchTerm: '',
    logLevel: [],
    timeRange: 'all',
    statusCodes: [],
    ipAddress: '',
    httpMethod: [],
    source: []
  })

  // Persist settings to localStorage
  useEffect(() => {
    localStorage.setItem('logManager_selectedLogType', selectedLogType)
  }, [selectedLogType])

  useEffect(() => {
    localStorage.setItem('logManager_tailLines', tailLines)
  }, [tailLines])

  useEffect(() => {
    localStorage.setItem('logManager_autoRefresh', String(autoRefresh))
  }, [autoRefresh])

  // supportsLogs and proxyName are now from useProxyCapabilities hook

  // CrowdSec logs (always available)
  const { data: crowdsecLogs, isLoading: crowdsecLoading, refetch: refetchCrowdsec } = useQuery({
    queryKey: ['logs-crowdsec', tailLines],
    queryFn: async () => {
      const response = await api.logs.getCrowdSec(tailLines)
      return response.data.data
    },
    refetchInterval: autoRefresh ? 5000 : false,
  })

  // Proxy logs (only if supported)
  const { data: proxyLogs, isLoading: proxyLoading, refetch: refetchProxy } = useQuery({
    queryKey: ['logs-proxy', proxyType, tailLines],
    queryFn: async () => {
      if (supportsLogs) {
        try {
          // Try the new generic proxy endpoint first
          const response = await api.logs.getProxy(tailLines)
          return response.data.data
        } catch (error) {
          // Fallback to specific proxy endpoints for backward compatibility
          if (proxyType === 'traefik') {
            const response = await api.logs.getTraefik(tailLines)
            return response.data.data
          } else if (proxyType === 'nginx') {
            const response = await api.logs.getService('nginx', tailLines)
            return response.data.data
          } else if (proxyType === 'caddy') {
            const response = await api.logs.getService('caddy', tailLines)
            return response.data.data
          } else if (proxyType === 'haproxy') {
            const response = await api.logs.getService('haproxy', tailLines)
            return response.data.data
          }
        }
      }
      return null
    },
    enabled: supportsLogs,
    refetchInterval: autoRefresh ? 5000 : false,
  })

  // Advanced log analytics (for supported proxies)
  const { data: logStats, isLoading: statsLoading, refetch: refetchStats } = useQuery({
    queryKey: ['logs-stats', proxyType, tailLines],
    queryFn: async () => {
      if (supportsLogs) {
        try {
          // Try the new generic proxy analytics endpoint first
          const response = await api.logs.analyzeProxy(tailLines)
          return response.data.data
        } catch (error) {
          // Fallback to Traefik-specific endpoint for backward compatibility
          if (proxyType === 'traefik') {
            const response = await api.logs.analyzeTraefikAdvanced(tailLines)
            return response.data.data
          }
        }
      }
      return null
    },
    enabled: supportsLogs,
    refetchInterval: autoRefresh ? 10000 : false,
  })

  const handleRefresh = () => {
    refetchCrowdsec()
    if (supportsLogs) {
      refetchProxy()
      refetchStats()
    }
  }

  const getAvailableLogTypes = () => {
    const types = [
      { value: 'crowdsec', label: 'CrowdSec Logs', available: true }
    ]
    
    if (supportsLogs) {
      types.push({
        value: 'proxy' as const,
        label: `${proxyName} Logs`,
        available: true
      })
    }
    
    return types
  }

  // Export functionality
  const handleExportLogs = () => {
    if (!filteredLogs.logs) return
    const blob = new Blob([filteredLogs.logs], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${selectedLogType}-logs-${new Date().toISOString()}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleExportStats = () => {
    if (!logStats) return
    const statsJson = JSON.stringify(logStats, null, 2)
    const blob = new Blob([statsJson], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${proxyType}-stats-${new Date().toISOString()}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleGenerateReport = () => {
    if (!logStats) return
    
    const report = `Log Analysis Report
Generated: ${new Date().toLocaleString()}
Proxy: ${proxyName}
Total Lines Processed: ${logStats.total_lines}

Top 5 IPs:
${logStats.top_ips.slice(0, 5).map(ip => `- ${ip.ip}: ${ip.count} requests`).join('\n')}

Status Code Distribution:
${Object.entries(logStats.status_codes).map(([code, count]) => `- ${code}: ${count}`).join('\n')}

Top 5 HTTP Methods:
${Object.entries(logStats.http_methods).sort((a,b) => b[1] - a[1]).slice(0, 5).map(([method, count]) => `- ${method}: ${count}`).join('\n')}
`
    const blob = new Blob([report], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `log-report-${new Date().toISOString()}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const availableLogTypes = getAvailableLogTypes()

  // Filter logs based on current filters
  const filteredLogs = useMemo(() => {
    const logs = selectedLogType === 'crowdsec' ? crowdsecLogs?.logs : proxyLogs?.logs
    if (!logs) return { logs: '', count: 0, originalCount: 0 }

    const lines = logs.split('\n').filter(line => line.trim())
    const originalCount = lines.length

    let filtered = lines

    // Apply search term filter
    if (logFilters.searchTerm) {
      const searchTerm = logFilters.searchTerm.toLowerCase()
      filtered = filtered.filter(line => 
        line.toLowerCase().includes(searchTerm)
      )
    }

    // Apply log level filter
    if (logFilters.logLevel.length > 0) {
      filtered = filtered.filter(line => {
        const levelMatch = line.match(/\s+(ERROR|WARN|WARNING|INFO|DEBUG)\s+/)
        if (levelMatch) {
          const level = levelMatch[1].toUpperCase()
          return logFilters.logLevel.includes(level) || 
                 (level === 'WARNING' && logFilters.logLevel.includes('WARN'))
        }
        return false
      })
    }

    // Apply IP address filter
    if (logFilters.ipAddress) {
      const ipFilter = logFilters.ipAddress.toLowerCase()
      filtered = filtered.filter(line => 
        line.toLowerCase().includes(ipFilter)
      )
    }

    // Apply HTTP method filter (for proxy logs)
    if (logFilters.httpMethod.length > 0 && selectedLogType === 'proxy') {
      filtered = filtered.filter(line => {
        return logFilters.httpMethod.some(method => 
          line.includes(`"${method} `) || line.includes(`${method} `)
        )
      })
    }

    // Apply status code filter (for proxy logs)
    if (logFilters.statusCodes.length > 0 && selectedLogType === 'proxy') {
      filtered = filtered.filter(line => {
        return logFilters.statusCodes.some(range => {
          if (range === '2xx') return /\s+2\d{2}\s+/.test(line)
          if (range === '3xx') return /\s+3\d{2}\s+/.test(line)
          if (range === '4xx') return /\s+4\d{2}\s+/.test(line)
          if (range === '5xx') return /\s+5\d{2}\s+/.test(line)
          return false
        })
      })
    }

    // Apply source filter
    if (logFilters.source.length > 0) {
      // This is a simplified implementation - in a real scenario, 
      // you'd need to identify log sources more accurately
      if (logFilters.source.includes('crowdsec') && selectedLogType !== 'crowdsec') {
        filtered = []
      }
      if (logFilters.source.includes(proxyType) && selectedLogType !== 'proxy') {
        filtered = []
      }
    }

    return {
      logs: filtered.join('\n'),
      count: filtered.length,
      originalCount
    }
  }, [crowdsecLogs, proxyLogs, selectedLogType, logFilters, proxyType])

  // Auto-select proxy logs if available and user hasn't made a selection
  useEffect(() => {
    if (supportsLogs && selectedLogType === 'crowdsec' && availableLogTypes.length > 1) {
      // Don't auto-switch, let user choose
    }
  }, [supportsLogs, selectedLogType, availableLogTypes.length])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Log Management</h1>
        <p className="text-muted-foreground mt-2">
          Monitor and analyze logs from CrowdSec and {proxyName}
        </p>
      </div>

      {/* Proxy Feature Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Network className="h-5 w-5" />
            Log Sources Configuration
          </CardTitle>
          <CardDescription>
            Available log sources for your current proxy configuration
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between p-4 border rounded-lg">
            <div>
              <p className="font-medium">Current Proxy Type</p>
              <p className="text-sm text-muted-foreground">
                {proxyName} {proxyType === 'zoraxy' && '(Experimental)'}
              </p>
            </div>
            <Badge variant="outline">{proxyName}</Badge>
          </div>

          <FeatureAvailabilityIndicator
            feature="logs"
            available={supportsLogs}
            proxyType={proxyType}
            description="Parse and analyze reverse proxy access logs"
          />

          <LogParsingStatus 
            proxyType={proxyType}
            supportsLogs={supportsLogs}
            logStats={logStats}
          />
        </CardContent>
      </Card>

      {/* Log Controls */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Filter className="h-5 w-5" />
            Log Controls
          </CardTitle>
          <CardDescription>
            Configure log viewing and refresh settings
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label htmlFor="log-type">Log Source</Label>
              <Select value={selectedLogType} onValueChange={(value: 'crowdsec' | 'proxy') => setSelectedLogType(value)}>
                <SelectTrigger id="log-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {availableLogTypes.map(type => (
                    <SelectItem 
                      key={type.value} 
                      value={type.value}
                      disabled={!type.available}
                    >
                      {type.label}
                      {!type.available && ' (Not Available)'}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="tail-lines">Lines to Show</Label>
              <Select value={tailLines} onValueChange={setTailLines}>
                <SelectTrigger id="tail-lines">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="50">50 lines</SelectItem>
                  <SelectItem value="100">100 lines</SelectItem>
                  <SelectItem value="200">200 lines</SelectItem>
                  <SelectItem value="500">500 lines</SelectItem>
                  <SelectItem value="1000">1000 lines</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Actions</Label>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleRefresh}
                  disabled={crowdsecLoading || proxyLoading}
                >
                  <RefreshCw className={`h-4 w-4 mr-2 ${crowdsecLoading || proxyLoading ? 'animate-spin' : ''}`} />
                  Refresh
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setAutoRefresh(!autoRefresh)}
                >
                  <Activity className="h-4 w-4 mr-2" />
                  {autoRefresh ? 'Stop' : 'Auto'}
                </Button>
              </div>
            </div>
          </div>

          {autoRefresh && (
            <Alert>
              <Activity className="h-4 w-4" />
              <AlertDescription>
                Auto-refresh is enabled. Logs will update every 5 seconds.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Log Filters */}
      <LogFilterPanel
        proxyType={proxyType}
        onFilterChange={setLogFilters}
        totalLogs={filteredLogs.originalCount}
        filteredLogs={filteredLogs.count}
      />

      {/* Log Content */}
      <Tabs defaultValue="viewer" className="space-y-4">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="viewer">
            <Eye className="h-4 w-4 mr-2" />
            Viewer
          </TabsTrigger>
          <TabsTrigger value="statistics" disabled={!logStats}>
            <BarChart3 className="h-4 w-4 mr-2" />
            Statistics
          </TabsTrigger>
          <TabsTrigger value="analytics" disabled={!logStats}>
            <TrendingUp className="h-4 w-4 mr-2" />
            Analytics
          </TabsTrigger>
          <TabsTrigger value="insights" disabled={!logStats}>
            <Activity className="h-4 w-4 mr-2" />
            Insights
          </TabsTrigger>
          <TabsTrigger value="settings">
            <Settings className="h-4 w-4 mr-2" />
            Settings
          </TabsTrigger>
        </TabsList>

        <TabsContent value="viewer">
          <LogViewer
            logType={selectedLogType}
            proxyType={proxyType}
            crowdsecLogs={selectedLogType === 'crowdsec' ? { logs: filteredLogs.logs } : crowdsecLogs}
            proxyLogs={selectedLogType === 'proxy' ? { logs: filteredLogs.logs, service: proxyType } : (proxyLogs ? { logs: proxyLogs.logs, service: proxyType } : undefined)}
            isLoading={selectedLogType === 'crowdsec' ? crowdsecLoading : proxyLoading}
            supportsLogs={supportsLogs}
            tailLines={tailLines}
          />
        </TabsContent>

        <TabsContent value="statistics">
          {logStats ? (
            <LogStatsDashboard
              logStats={logStats}
              proxyType={proxyType}
              isLoading={statsLoading}
              onRefresh={refetchStats}
              timeRange={logFilters.timeRange}
            />
          ) : (
            <Card>
              <CardContent className="p-8 text-center">
                <BarChart3 className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium mb-2">Statistics Not Available</h3>
                <p className="text-muted-foreground mb-4">
                  Log statistics are only available for proxies with log parsing support.
                </p>
                {!supportsLogs && (
                  <Alert className="max-w-md mx-auto">
                    <Info className="h-4 w-4" />
                    <AlertDescription>
                      {proxyName} does not support log parsing. Consider using Traefik for comprehensive log analytics.
                    </AlertDescription>
                  </Alert>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="analytics">
          {logStats ? (
            <LogAnalyticsDashboard
              logStats={logStats}
              proxyType={proxyType}
              isLoading={statsLoading}
              onRefresh={refetchStats}
            />
          ) : (
            <Card>
              <CardContent className="p-8 text-center">
                <BarChart3 className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium mb-2">Analytics Not Available</h3>
                <p className="text-muted-foreground mb-4">
                  Log analytics are only available for Traefik with log parsing support.
                </p>
                {proxyType !== 'traefik' && (
                  <Alert className="max-w-md mx-auto">
                    <Info className="h-4 w-4" />
                    <AlertDescription>
                      Consider upgrading to Traefik for advanced log analytics and insights.
                    </AlertDescription>
                  </Alert>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="insights">
          {logStats ? (
            <LogInsightsDashboard
              logStats={logStats}
              proxyType={proxyType}
              isLoading={statsLoading}
              onRefresh={refetchStats}
            />
          ) : (
            <Card>
              <CardContent className="p-8 text-center">
                <TrendingUp className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium mb-2">Insights Not Available</h3>
                <p className="text-muted-foreground mb-4">
                  Advanced insights require log parsing support and analytics data.
                </p>
                {proxyType !== 'traefik' && (
                  <Alert className="max-w-md mx-auto">
                    <Info className="h-4 w-4" />
                    <AlertDescription>
                      Traefik provides the most comprehensive log insights and analytics.
                    </AlertDescription>
                  </Alert>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="settings">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                Log Management Settings
              </CardTitle>
              <CardDescription>
                Configure log viewing and analysis preferences
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Refresh Settings */}
              <div className="space-y-3">
                <h4 className="font-medium">Refresh Settings</h4>
                <div className="flex items-center gap-4">
                  <Button
                    variant={autoRefresh ? "default" : "outline"}
                    size="sm"
                    onClick={() => setAutoRefresh(!autoRefresh)}
                  >
                    <Activity className="h-4 w-4 mr-2" />
                    {autoRefresh ? 'Auto-Refresh On' : 'Auto-Refresh Off'}
                  </Button>
                  {autoRefresh && (
                    <Badge variant="secondary">
                      Updates every 5 seconds
                    </Badge>
                  )}
                </div>
              </div>

              {/* Log Format Settings */}
              <div className="space-y-3">
                <h4 className="font-medium">Display Preferences</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Default Log Source</Label>
                    <Select value={selectedLogType} onValueChange={(value: 'crowdsec' | 'proxy') => setSelectedLogType(value)}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="crowdsec">CrowdSec Logs</SelectItem>
                        {supportsLogs && (
                          <SelectItem value="proxy">{proxyName} Logs</SelectItem>
                        )}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Lines to Display</Label>
                    <Select value={tailLines} onValueChange={setTailLines}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="50">50 lines</SelectItem>
                        <SelectItem value="100">100 lines</SelectItem>
                        <SelectItem value="200">200 lines</SelectItem>
                        <SelectItem value="500">500 lines</SelectItem>
                        <SelectItem value="1000">1000 lines</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </div>

              {/* Proxy-Specific Settings */}
              {supportsLogs && (
                <div className="space-y-3">
                  <h4 className="font-medium">{proxyName} Log Settings</h4>
                  <Alert>
                    <Info className="h-4 w-4" />
                    <AlertDescription>
                      {proxyType === 'traefik' && 'Traefik provides comprehensive log parsing with JSON and Common Log Format support.'}
                      {proxyType === 'nginx' && 'Nginx Proxy Manager logs are parsed from standard access log files.'}
                      {proxyType === 'caddy' && 'Caddy structured logging provides detailed request information.'}
                      {proxyType === 'haproxy' && 'HAProxy syslog format is supported for basic request tracking.'}
                      {proxyType === 'zoraxy' && 'Zoraxy log parsing is experimental and may have limited functionality.'}
                    </AlertDescription>
                  </Alert>
                </div>
              )}

              {/* Export Options */}
              <div className="space-y-3">
                <h4 className="font-medium">Export Options</h4>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={handleExportLogs} disabled={!filteredLogs.logs}>
                    Export Filtered Logs
                  </Button>
                  <Button variant="outline" size="sm" onClick={handleExportStats} disabled={!logStats}>
                    Export Statistics
                  </Button>
                  <Button variant="outline" size="sm" onClick={handleGenerateReport} disabled={!logStats}>
                    Generate Report
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Fallback for unsupported proxies */}
      {!supportsLogs && (
        <Card>
          <CardHeader>
            <CardTitle>Alternative Log Solutions</CardTitle>
            <CardDescription>
              Log monitoring options for {proxyName}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Alert>
              <Info className="h-4 w-4" />
              <AlertDescription>
                While {proxyName} doesn't support built-in log parsing, you can still monitor logs:
              </AlertDescription>
            </Alert>

            <div className="space-y-3">
              <div className="p-4 border rounded-lg">
                <h4 className="font-medium">Direct Log Access</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  Access {proxyName} logs directly through container logs or log files
                </p>
              </div>

              <div className="p-4 border rounded-lg">
                <h4 className="font-medium">External Log Management</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  Use external log aggregation tools like ELK Stack, Grafana, or Splunk
                </p>
              </div>

              <div className="p-4 border rounded-lg">
                <h4 className="font-medium">CrowdSec Logs Available</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  Monitor CrowdSec security events and decisions through the CrowdSec logs
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}