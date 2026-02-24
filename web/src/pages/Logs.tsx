import { useState, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import api from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { FileText, RefreshCw, Activity } from 'lucide-react'
import { PageHeader, QueryError } from '@/components/common'
import { TraefikAnalytics } from '@/components/logs/TraefikAnalytics'

export default function Logs() {
  const [selectedService, setSelectedService] = useState<'crowdsec' | 'traefik'>('crowdsec')
  const [tailLines, setTailLines] = useState('100')
  const [isStreaming, setIsStreaming] = useState(false)
  const [streamLogs, setStreamLogs] = useState<string[]>([])
  const wsRef = useRef<WebSocket | null>(null)
  const logEndRef = useRef<HTMLDivElement>(null)
  const prevStreamLengthRef = useRef<number>(0)

  const { data: crowdsecLogs, isLoading: crowdsecLoading, isError: isCrowdsecError, error: crowdsecError, refetch: refetchCrowdSec } = useQuery({
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
        ws.onopen = () => { toast.success('Log stream connected'); setStreamLogs([]); prevStreamLengthRef.current = 0 }
        ws.onmessage = (event: MessageEvent) => {
          const message = (event.data as string)?.trim()
          if (!message) return
          const lines = message.split('\n').filter(line => line.trim().length > 0)
          if (lines.length === 0) return
          setStreamLogs(prev => {
            const lastFewLines = prev.slice(-5)
            const hasNewContent = lines.some(line => !lastFewLines.includes(line))
            if (!hasNewContent && prev.length > 0) return prev
            return [...prev, ...lines]
          })
        }
        ws.onerror = () => { toast.error('WebSocket error occurred'); setIsStreaming(false) }
        ws.onclose = () => { toast.info('Log stream disconnected'); setIsStreaming(false) }
      } catch {
        toast.error('Failed to connect to log stream')
        setIsStreaming(false)
      }
      return () => { if (wsRef.current) wsRef.current.close(); prevStreamLengthRef.current = 0 }
    } else {
      setStreamLogs([])
      prevStreamLengthRef.current = 0
      if (wsRef.current) { wsRef.current.close(); wsRef.current = null }
    }
  }, [isStreaming, selectedService])

  useEffect(() => {
    if (isStreaming) {
      const currentLength = streamLogs.length
      if (currentLength > prevStreamLengthRef.current && logEndRef.current) {
        logEndRef.current.scrollIntoView({ behavior: 'smooth' })
        prevStreamLengthRef.current = currentLength
      }
    } else if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [streamLogs, crowdsecLogs, traefikLogs, isStreaming])

  const switchService = (service: 'crowdsec' | 'traefik') => {
    if (isStreaming && wsRef.current) { wsRef.current.close(); wsRef.current = null }
    setSelectedService(service)
    setStreamLogs([])
    prevStreamLengthRef.current = 0
    setIsStreaming(false)
  }

  const handleToggleStream = () => {
    if (isStreaming) {
      if (wsRef.current) { wsRef.current.close(); wsRef.current = null }
      setStreamLogs([])
      prevStreamLengthRef.current = 0
      setIsStreaming(false)
    } else {
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
      <PageHeader title="Logs Viewer" description="View and analyze service logs in real-time" />

      {isCrowdsecError && <QueryError error={crowdsecError} onRetry={refetchCrowdSec} />}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />Service Logs
          </CardTitle>
          <CardDescription>Select a service to view its logs</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Button variant={selectedService === 'crowdsec' ? 'default' : 'outline'} onClick={() => switchService('crowdsec')} className="flex-1">CrowdSec Logs</Button>
            <Button variant={selectedService === 'traefik' ? 'default' : 'outline'} onClick={() => switchService('traefik')} className="flex-1">Traefik Logs</Button>
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Label htmlFor="tail-lines">Lines:</Label>
                <select id="tail-lines" className="h-9 rounded-md border border-input bg-background px-3 text-sm" value={tailLines} onChange={(e) => setTailLines(e.target.value)} disabled={isStreaming}>
                  <option value="50">50</option>
                  <option value="100">100</option>
                  <option value="200">200</option>
                  <option value="500">500</option>
                  <option value="1000">1000</option>
                </select>
              </div>
              <div className="flex items-center gap-2">
                <Switch id="streaming" checked={isStreaming} onCheckedChange={handleToggleStream} />
                <Label htmlFor="streaming" className="cursor-pointer">Live Stream</Label>
              </div>
            </div>
            <Button onClick={() => { selectedService === 'crowdsec' ? refetchCrowdSec() : refetchTraefik(); toast.success('Logs refreshed') }} disabled={isLoading || isStreaming} size="sm" variant="outline">
              <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />Refresh
            </Button>
          </div>
          {isStreaming && (
            <div className="flex items-center gap-2 p-2 bg-emerald-500/10 border border-emerald-500/20 rounded">
              <Activity className="h-4 w-4 text-emerald-600 dark:text-emerald-400 animate-pulse" />
              <span className="text-sm text-emerald-600 dark:text-emerald-400">Live streaming {selectedService} logs...</span>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Log Output</CardTitle>
            <Badge variant="secondary">{selectedService === 'crowdsec' ? 'CrowdSec' : 'Traefik'}</Badge>
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
                  <Badge variant="secondary" className="text-xs">{currentLogs.split('\n').length} lines</Badge>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {selectedService === 'traefik' && (
        <TraefikAnalytics stats={traefikStats} isLoading={statsLoading} onRefresh={() => refetchStats()} />
      )}
    </div>
  )
}
