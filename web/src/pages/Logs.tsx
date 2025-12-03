import { useState, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import api from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { FileText, RefreshCw, Activity, BarChart3 } from 'lucide-react'

export default function Logs() {
  const [selectedService, setSelectedService] = useState<'crowdsec' | 'traefik'>('crowdsec')
  const [tailLines, setTailLines] = useState('100')
  const [isStreaming, setIsStreaming] = useState(false)
  const [streamLogs, setStreamLogs] = useState<string[]>([])
  const wsRef = useRef<WebSocket | null>(null)
  const logEndRef = useRef<HTMLDivElement>(null)
  const prevStreamLengthRef = useRef<number>(0)

  const { data: crowdsecLogs, isLoading: crowdsecLoading, refetch: refetchCrowdSec } = useQuery({
    queryKey: ['logs-crowdsec', tailLines],
    queryFn: async () => {
      const response = await api.logs.getCrowdSec(tailLines)
      return response.data.data
    },
    enabled: selectedService === 'crowdsec' && !isStreaming,
  })

  const { data: traefikLogs, isLoading: traefikLoading, refetch: refetchTraefik } = useQuery({
    queryKey: ['logs-traefik', tailLines],
    queryFn: async () => {
      const response = await api.logs.getTraefik(tailLines)
      return response.data.data
    },
    enabled: selectedService === 'traefik' && !isStreaming,
  })

  const { data: traefikStats, isLoading: statsLoading, refetch: refetchStats } = useQuery({
    queryKey: ['logs-traefik-stats'],
    queryFn: async () => {
      const response = await api.logs.analyzeTraefikAdvanced('1000')
      return response.data.data
    },
  })

  // WebSocket streaming
  useEffect(() => {
    if (isStreaming) {
      const wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}${api.logs.getStreamUrl(selectedService)}`

      try {
        const ws = new WebSocket(wsUrl)
        wsRef.current = ws

        ws.onopen = () => {
          toast.success('Log stream connected')
          setStreamLogs([])
          prevStreamLengthRef.current = 0
        }

        ws.onmessage = (event: MessageEvent) => {
          // Filter out empty messages
          const message = (event.data as string)?.trim()
          if (!message || message === '') {
            return
          }

          // Split message into lines and filter empty lines
          const lines = message.split('\n').filter(line => line.trim().length > 0)
          if (lines.length === 0) {
            return
          }

          // Only update if there are actual new lines
          setStreamLogs(prev => {
            // Check if these lines are duplicates by comparing with last few lines
            const lastFewLines = prev.slice(-5)
            const hasNewContent = lines.some(line => !lastFewLines.includes(line))
            
            if (!hasNewContent && prev.length > 0) {
              // No new content, don't update
              return prev
            }

            // Add new lines
            return [...prev, ...lines]
          })
        }

        ws.onerror = () => {
          toast.error('WebSocket error occurred')
          setIsStreaming(false)
        }

        ws.onclose = () => {
          toast.info('Log stream disconnected')
          setIsStreaming(false)
        }
      } catch (error) {
        toast.error('Failed to connect to log stream')
        setIsStreaming(false)
      }

      return () => {
        if (wsRef.current) {
          wsRef.current.close()
        }
        prevStreamLengthRef.current = 0
      }
    } else {
      // Reset stream logs when stopping stream
      setStreamLogs([])
      prevStreamLengthRef.current = 0
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
    }
  }, [isStreaming, selectedService])

  // Auto-scroll to bottom - only when there's actual new content
  useEffect(() => {
    if (isStreaming) {
      // Only scroll if streamLogs actually increased
      const currentLength = streamLogs.length
      if (currentLength > prevStreamLengthRef.current && logEndRef.current) {
        logEndRef.current.scrollIntoView({ behavior: 'smooth' })
        prevStreamLengthRef.current = currentLength
      }
    } else {
      // For non-streaming, scroll when logs change
      if (logEndRef.current) {
        logEndRef.current.scrollIntoView({ behavior: 'smooth' })
      }
    }
  }, [streamLogs, crowdsecLogs, traefikLogs, isStreaming])

  const handleRefresh = () => {
    if (selectedService === 'crowdsec') {
      refetchCrowdSec()
    } else {
      refetchTraefik()
    }
    toast.success('Logs refreshed')
  }

  const handleToggleStream = () => {
    if (isStreaming) {
      // Stop streaming
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
      setStreamLogs([])
      prevStreamLengthRef.current = 0
      setIsStreaming(false)
    } else {
      // Start streaming
      setIsStreaming(true)
    }
  }

  const currentLogs = isStreaming
    ? streamLogs.filter(line => line.trim().length > 0).join('\n')
    : selectedService === 'crowdsec'
      ? crowdsecLogs?.logs || ''
      : traefikLogs?.logs || ''

  const isLoading = selectedService === 'crowdsec' ? crowdsecLoading : traefikLoading

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Logs Viewer</h1>
        <p className="text-muted-foreground mt-2">
          View and analyze service logs in real-time
        </p>
      </div>

      {/* Service Selector */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Service Logs
          </CardTitle>
          <CardDescription>
            Select a service to view its logs
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Button
              variant={selectedService === 'crowdsec' ? 'default' : 'outline'}
              onClick={() => {
                if (isStreaming && wsRef.current) {
                  wsRef.current.close()
                  wsRef.current = null
                }
                setSelectedService('crowdsec')
                setStreamLogs([])
                prevStreamLengthRef.current = 0
                setIsStreaming(false)
              }}
              className="flex-1"
            >
              CrowdSec Logs
            </Button>
            <Button
              variant={selectedService === 'traefik' ? 'default' : 'outline'}
              onClick={() => {
                if (isStreaming && wsRef.current) {
                  wsRef.current.close()
                  wsRef.current = null
                }
                setSelectedService('traefik')
                setStreamLogs([])
                prevStreamLengthRef.current = 0
                setIsStreaming(false)
              }}
              className="flex-1"
            >
              Traefik Logs
            </Button>
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Label htmlFor="tail-lines">Lines:</Label>
                <select
                  id="tail-lines"
                  className="h-9 rounded-md border border-input bg-background px-3 text-sm"
                  value={tailLines}
                  onChange={(e) => setTailLines(e.target.value)}
                  disabled={isStreaming}
                >
                  <option value="50">50</option>
                  <option value="100">100</option>
                  <option value="200">200</option>
                  <option value="500">500</option>
                  <option value="1000">1000</option>
                </select>
              </div>

              <div className="flex items-center gap-2">
                <Switch
                  id="streaming"
                  checked={isStreaming}
                  onCheckedChange={handleToggleStream}
                />
                <Label htmlFor="streaming" className="cursor-pointer">
                  Live Stream
                </Label>
              </div>
            </div>

            <Button
              onClick={handleRefresh}
              disabled={isLoading || isStreaming}
              size="sm"
              variant="outline"
            >
              <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>

          {isStreaming && (
            <div className="flex items-center gap-2 p-2 bg-green-500/10 border border-green-500/20 rounded">
              <Activity className="h-4 w-4 text-green-500 animate-pulse" />
              <span className="text-sm text-green-500">
                Live streaming {selectedService} logs...
              </span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Log Output */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Log Output</CardTitle>
            <Badge variant="secondary">
              {selectedService === 'crowdsec' ? 'CrowdSec' : 'Traefik'}
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading && !isStreaming ? (
            <div className="h-96 bg-muted animate-pulse rounded" />
          ) : (
            <div className="relative">
              <pre className="bg-black text-green-400 p-4 rounded-lg overflow-x-auto max-h-96 overflow-y-auto text-xs font-mono">
                {currentLogs || 'No logs available'}
                <div ref={logEndRef} />
              </pre>
              {currentLogs && (
                <div className="absolute top-2 right-2">
                  <Badge variant="secondary" className="text-xs">
                    {currentLogs.split('\n').length} lines
                  </Badge>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Traefik Advanced Analytics */}
      {selectedService === 'traefik' && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <BarChart3 className="h-5 w-5" />
                  Advanced Analytics
                </CardTitle>
                <CardDescription>
                  Traffic analysis from Traefik access logs
                </CardDescription>
              </div>
              <Button
                onClick={() => refetchStats()}
                disabled={statsLoading}
                size="sm"
                variant="outline"
              >
                <RefreshCw className={`mr-2 h-4 w-4 ${statsLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {statsLoading ? (
              <div className="space-y-2">
                <div className="h-24 bg-muted animate-pulse rounded" />
                <div className="h-24 bg-muted animate-pulse rounded" />
              </div>
            ) : traefikStats ? (
              <div className="space-y-6">
                {/* Summary */}
                <div className="grid gap-4 md:grid-cols-3">
                  <div className="p-4 border rounded-lg">
                    <p className="text-sm text-muted-foreground">Total Requests</p>
                    <p className="text-2xl font-bold">{traefikStats.total_lines || 0}</p>
                  </div>
                  <div className="p-4 border rounded-lg">
                    <p className="text-sm text-muted-foreground">Unique IPs</p>
                    <p className="text-2xl font-bold">{traefikStats.top_ips?.length || 0}</p>
                  </div>
                  <div className="p-4 border rounded-lg">
                    <p className="text-sm text-muted-foreground">Error Entries</p>
                    <p className="text-2xl font-bold">{traefikStats.error_entries?.length || 0}</p>
                  </div>
                </div>

                {/* Top IPs */}
                {traefikStats.top_ips && traefikStats.top_ips.length > 0 && (
                  <div>
                    <h3 className="font-semibold mb-2">Top IP Addresses</h3>
                    <div className="space-y-2">
                      {traefikStats.top_ips.slice(0, 10).map((ipData: any, index: number) => (
                        <div key={index} className="flex items-center justify-between p-2 border rounded">
                          <span className="font-mono text-sm">{ipData.ip}</span>
                          <Badge>{ipData.count} requests</Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Status Codes */}
                {traefikStats.status_codes && Object.keys(traefikStats.status_codes).length > 0 && (
                  <div>
                    <h3 className="font-semibold mb-2">HTTP Status Codes</h3>
                    <div className="grid gap-2 md:grid-cols-3">
                      {Object.entries(traefikStats.status_codes).map(([code, count]) => (
                        <div key={code} className="flex items-center justify-between p-2 border rounded">
                          <span className="font-mono text-sm">{code}</span>
                          <Badge variant={code.startsWith('2') ? 'default' : code.startsWith('4') ? 'secondary' : 'destructive'}>
                            {String(count)}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* HTTP Methods */}
                {traefikStats.http_methods && Object.keys(traefikStats.http_methods).length > 0 && (
                  <div>
                    <h3 className="font-semibold mb-2">HTTP Methods</h3>
                    <div className="grid gap-2 md:grid-cols-4">
                      {Object.entries(traefikStats.http_methods).map(([method, count]) => (
                        <div key={method} className="flex items-center justify-between p-2 border rounded">
                          <span className="font-mono text-sm">{method}</span>
                          <Badge>{String(count)}</Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-center text-muted-foreground py-8">
                No analytics data available
              </p>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
