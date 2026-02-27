import { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import api from '@/lib/api'
import { ErrorContexts, getErrorMessage } from '@/lib/api/errors'
import { useSearch } from '@/contexts/SearchContext'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Label } from '@/components/ui/label'
import { FileText, RefreshCw, Activity, Download } from 'lucide-react'
import { PageHeader, QueryError } from '@/components/common'
import { LogFilterPanel, type LogFilters } from '@/components/logs/LogFilterPanel'
import { LogViewer } from '@/components/logs/LogViewer'
import { TraefikAnalytics } from '@/components/logs/TraefikAnalytics'

export default function Logs() {
  const [selectedService, setSelectedService] = useState<'crowdsec' | 'traefik'>('crowdsec')
  const [tailLines, setTailLines] = useState('100')
  const [isStreaming, setIsStreaming] = useState(false)
  const [streamLogs, setStreamLogs] = useState<string[]>([])
  const { query, setQuery } = useSearch()
  const [filters, setFilters] = useState<LogFilters>({
    service: 'crowdsec',
    level: 'all',
    search: '',
  })
  const wsRef = useRef<WebSocket | null>(null)
  const prevStreamLengthRef = useRef<number>(0)

  const { data: crowdsecLogs, isLoading: crowdsecLoading, isError: isCrowdsecError, error: crowdsecError, refetch: refetchCrowdSec } = useQuery({
    queryKey: ['logs-crowdsec', tailLines],
    queryFn: async () => {
      const response = await api.logs.getCrowdSec(tailLines)
      return response.data.data ?? null
    },
    enabled: selectedService === 'crowdsec' && !isStreaming,
  })

  const { data: traefikLogs, isLoading: traefikLoading, refetch: refetchTraefik } = useQuery({
    queryKey: ['logs-traefik', tailLines],
    queryFn: async () => {
      const response = await api.logs.getTraefik(tailLines)
      return response.data.data ?? null
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
        ws.onerror = (event) => { toast.error(getErrorMessage(event, 'WebSocket error occurred', ErrorContexts.LogsStreamWebsocketError)); setIsStreaming(false) }
        ws.onclose = () => { toast.info('Log stream disconnected'); setIsStreaming(false) }
      } catch (error) {
        toast.error(getErrorMessage(error, 'Failed to connect to log stream', ErrorContexts.LogsStreamConnect))
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
    if (filters.service === 'all') {
      return
    }
    if (filters.service !== selectedService) {
      setSelectedService(filters.service as 'crowdsec' | 'traefik')
    }
  }, [filters.service, selectedService])

  useEffect(() => {
    if (filters.search !== query) {
      setFilters((prev) => ({ ...prev, search: query }))
    }
  }, [query, filters.search])

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

  const rawLogs = isStreaming
    ? streamLogs.filter(line => line.trim().length > 0).join('\n')
    : selectedService === 'crowdsec'
      ? crowdsecLogs?.logs || ''
      : traefikLogs?.logs || ''

  // Filter logs by search term and level
  const filteredLines = useMemo(() => {
    if (!rawLogs) return []
    let lines = rawLogs.split('\n').filter(l => l.trim())

    if (filters.level !== 'all') {
      lines = lines.filter(line => {
        const match = line.match(/\b(ERROR|WARN(?:ING)?|INFO|DEBUG)\b/)
        if (!match) return false
        const normalized = match[1] === 'WARNING' ? 'WARN' : match[1]
        return normalized === filters.level.toUpperCase()
      })
    }

    if (filters.search) {
      const lower = filters.search.toLowerCase()
      lines = lines.filter(line => line.toLowerCase().includes(lower))
    }

    return lines
  }, [rawLogs, filters.search, filters.level])

  const totalLines = rawLogs ? rawLogs.split('\n').filter(l => l.trim()).length : 0

  const handleExport = useCallback(() => {
    if (!filteredLines.length) return
    const blob = new Blob([filteredLines.join('\n')], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${selectedService}-logs-${new Date().toISOString().slice(0, 19)}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    toast.success('Logs exported')
  }, [filteredLines, selectedService])

  const isLoading = selectedService === 'crowdsec' ? crowdsecLoading : traefikLoading

  return (
    <div className="space-y-6">
      <PageHeader
        title="Logs Viewer"
        description="View and analyze service logs in real-time"
        breadcrumbs="System / Logs"
      />

      {isCrowdsecError && <QueryError error={crowdsecError} onRetry={refetchCrowdSec} />}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />Service Logs
          </CardTitle>
          <CardDescription>Select a service to view its logs</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
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
              <div className="hidden md:flex items-center gap-1">
                {['100', '500', '1000'].map((preset) => (
                  <Button
                    key={preset}
                    variant={tailLines === preset ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setTailLines(preset)}
                    disabled={isStreaming}
                  >
                    {preset}
                  </Button>
                ))}
              </div>
              <Button variant="outline" size="sm" onClick={handleToggleStream}>
                {isStreaming ? 'Pause Stream' : 'Start Stream'}
              </Button>
            </div>
            <Button onClick={() => { selectedService === 'crowdsec' ? refetchCrowdSec() : refetchTraefik(); toast.success('Logs refreshed') }} disabled={isLoading || isStreaming} size="sm" variant="outline">
              <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />Refresh
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

      {/* Search, Filter & Export Controls */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-col gap-3">
            <LogFilterPanel
              services={['crowdsec', 'traefik']}
              filters={filters}
              includeAllServices={false}
              onFilterChange={(next) => {
                setFilters(next)
                if (next.search !== query) {
                  setQuery(next.search)
                }
              }}
            />
            <div className="flex items-center justify-between">
              <div className="text-xs text-muted-foreground">
                Showing {filteredLines.length} of {totalLines} lines
              </div>
              <Button variant="outline" size="sm" onClick={handleExport} disabled={!filteredLines.length}>
                <Download className="h-4 w-4" />Export
              </Button>
            </div>
          </div>
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
            <LogViewer logs={filteredLines} autoScroll />
          )}
        </CardContent>
      </Card>

      {selectedService === 'traefik' && (
        <TraefikAnalytics stats={traefikStats || undefined} isLoading={statsLoading} onRefresh={() => refetchStats()} />
      )}
    </div>
  )
}
