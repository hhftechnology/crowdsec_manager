import { useState, useMemo, useCallback, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import { 
  ResponsiveContainer, 
  RadialBarChart, 
  RadialBar, 
  PolarAngleAxis 
} from 'recharts'
import { 
  LayoutDashboard, 
  Route, 
  Globe, 
  Cpu, 
  FileText,
  Activity,
  AlertTriangle,
  Clock,
  Users,
  TrendingUp,
  Zap,
  Server,
  Network,
  Monitor,
  HardDrive,
  Cpu as CpuIcon,
  MemoryStick,
  Check
} from 'lucide-react'
import api from '@/lib/api'
import { dashboardAPI, type DashboardRange } from '@/lib/api/dashboard'
import { ErrorContexts, getErrorMessage } from '@/lib/api/errors'
import { cn, getMethodStyles, getStatusVariant, parseTraefikLog, groupStatusCodes } from '@/lib/utils'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { PageHeader } from '@/components/common'
import { LogProcessingToggle, useLogProcessingControl } from '@/components/logs/LogProcessingToggle'
import { useSearch } from '@/contexts/SearchContext'
import { useMountEffect } from '@/hooks/useMountEffect'
import { RangeSelector } from '@/features/logs/dashboard'

// Traefik Sections
import { StatCard, ChartCard, AreaTimeline, PieBreakdown, BarDistribution, ThreatMap } from '@/components/charts'

// We will render sections manually in Tabs!
// This adapts Traefik Log Dashboard UI into CrowdSec Manager.

function formatNumber(n: number): string { return n.toLocaleString() }
function formatPercent(n: number): string { return `${(n * 100).toFixed(1)}%` }
function formatDuration(ms: number | null | undefined): string {
  if (ms == null) return '—'
  const value = ms
  if (value < 1) return `${(value * 1000).toFixed(0)} µs`
  if (value < 1000) return `${value.toFixed(1)} ms`
  return `${(value / 1000).toFixed(2)} s`
}

function parseUserAgent(ua: string) {
  if (!ua) return { browser: 'Unknown', os: 'Unknown', cpu: 'Unknown', device: 'Unknown' };

  let browser = 'Unknown';
  let os = 'Unknown';
  let cpu = 'Unknown';
  let device = 'Unknown';

  // Browser
  if (ua.includes('Firefox/')) browser = 'Firefox ' + ua.split('Firefox/')[1].split(' ')[0];
  else if (ua.includes('Edg/')) browser = 'Edge ' + ua.split('Edg/')[1].split(' ')[0];
  else if (ua.includes('Chrome/')) browser = 'Chrome ' + ua.split('Chrome/')[1].split(' ')[0];
  else if (ua.includes('Safari/') && !ua.includes('Chrome')) browser = 'Safari ' + ua.split('Safari/')[1].split(' ')[0];

  // OS
  if (ua.includes('Android')) {
    os = 'Android ' + (ua.match(/Android ([\d.]+)/)?.[1] || '');
  } else if (ua.includes('iPhone') || ua.includes('iPad')) {
    os = 'iOS ' + (ua.match(/OS ([\d_]+)/)?.[1]?.replace(/_/g, '.') || '');
    device = ua.includes('iPhone') ? 'iPhone' : 'iPad';
  } else if (ua.includes('Windows NT')) {
    const ver = ua.match(/Windows NT ([\d.]+)/)?.[1];
    os = ver === '10.0' ? 'Windows 10/11' : ver === '6.3' ? 'Windows 8.1' : ver === '6.2' ? 'Windows 8' : ver === '6.1' ? 'Windows 7' : 'Windows';
  } else if (ua.includes('Mac OS X')) {
    os = 'macOS ' + (ua.match(/Mac OS X ([\d_]+)/)?.[1]?.replace(/_/g, '.') || '');
  } else if (ua.includes('Linux')) {
    os = 'Linux';
  }

  // CPU
  if (ua.includes('arm_64') || ua.includes('aarch64') || ua.includes('arm64')) cpu = 'ARM 64-bit';
  else if (ua.includes('x86_64') || ua.includes('amd64')) cpu = 'x86 64-bit';
  else if (ua.includes('i386') || ua.includes('i686')) cpu = 'x86 32-bit';

  // Device (Model specific)
  const deviceMatch = ua.match(/\(([^)]+)\)/);
  if (deviceMatch && device === 'Unknown') {
    const parts = deviceMatch[1].split(';');
    // Take the last part or part that looks like a model
    for (const part of parts) {
      const p = part.trim();
      if (p.includes('Android') || p.includes('Linux') || p.includes('Windows') || p.includes('Macintosh')) continue;
      if (p.length > 2) {
        device = p;
        break;
      }
    }
  }

  return { browser, os, cpu, device };
}

function TraefikLogDetail({ log, open, onOpenChange }: { log: any, open: boolean, onOpenChange: (open: boolean) => void }) {
  if (!log) return null;

  const uaInfo = parseUserAgent(log["request_User-Agent"] || log.UserAgent);

  const Section = ({ title, children }: { title: string, children: React.ReactNode }) => (
    <div className="space-y-2">
      <h4 className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70 px-1">{title}</h4>
      <div className="rounded-lg border bg-muted/30 divide-y divide-border/50 overflow-hidden">
        {children}
      </div>
    </div>
  )

  const Field = ({ label, value }: { label: string, value: any }) => {
    if (value === undefined || value === null || value === '') return null
    return (
      <div className="flex items-start justify-between gap-4 px-3 py-2 text-xs">
        <span className="text-muted-foreground shrink-0">{label}</span>
        <span className="font-mono text-right break-all">{String(value)}</span>
      </div>
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Badge className={cn("font-bold", getMethodStyles(log.method))}>{log.method}</Badge>
            <Badge variant={getStatusVariant(log.status)}>{log.status}</Badge>
            <span className="ml-2 text-sm font-mono truncate">{log.path}</span>
          </DialogTitle>
          <DialogDescription>Detailed log entry information</DialogDescription>
        </DialogHeader>

        <div className="space-y-6 mt-4">
          {/* User Agent Breakdown Boxes */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'App/Browser', value: uaInfo.browser, icon: Monitor },
              { label: 'Sistema Operativo', value: uaInfo.os, icon: Activity },
              { label: 'Processore', value: uaInfo.cpu, icon: CpuIcon },
              { label: 'Dispositivo', value: uaInfo.device, icon: Users },
            ].map((box, i) => (
              <div key={i} className="flex flex-col items-center justify-center p-3 rounded-xl bg-primary/5 border border-primary/10 hover:bg-primary/10 transition-colors text-center group">
                <box.icon className="h-4 w-4 mb-2 text-primary group-hover:scale-110 transition-transform" />
                <span className="text-[9px] font-bold uppercase text-muted-foreground mb-1">{box.label}</span>
                <span className="text-[11px] font-semibold truncate w-full" title={box.value}>{box.value}</span>
              </div>
            ))}
          </div>

          <Section title="Request Information">
            <Field label="Full URL" value={log.RequestAddr || (log.RequestHost ? log.RequestHost + log.path : undefined)} />
            <Field label="Method" value={log.method} />
            <Field label="Protocol" value={log.RequestProtocol} />
            <Field label="User Agent" value={log["request_User-Agent"] || log.UserAgent} />
            <Field label="Referer" value={log["request_Referer"]} />
          </Section>

          <Section title="Response Detail">
            <Field label="Status Code" value={log.status} />
            <Field label="Duration" value={formatDuration(log.Duration ?? log.duration)} />
            <Field label="Content Size" value={log.DownstreamContentSize ? formatBytes(log.DownstreamContentSize) : undefined} />
            <Field label="Content Type" value={log["downstream_Content-Type"]} />
          </Section>

          <Section title="Routing & Backend">
            <Field label="Router Name" value={log.RouterName} />
            <Field label="Service Name" value={log.service} />
            <Field label="Service Address" value={log.ServiceAddr} />
            <Field label="Entry Point" value={log.entryPointName} />
          </Section>

          <Section title="Client & Geography">
            <Field label="Client IP" value={log.ip} />
            <Field label="Client Port" value={log.ClientPort} />
            <Field label="Country" value={log.geoCountry} />
            <Field label="City" value={log.geoCity} />
          </Section>

          <Section title="Timestamps">
            <Field label="Start (Local)" value={log.StartLocal} />
            <Field label="Start (UTC)" value={log.StartUTC || log.t} />
          </Section>
        </div>
      </DialogContent>
    </Dialog>
  )
}

function HealthBar({ segments }: { segments: { label: string, count: number, variant: 'success' | 'warning' | 'destructive' }[] }) {
  const total = segments.reduce((acc, s) => acc + s.count, 0)
  return (
    <Card className="hover:shadow-md transition-shadow">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold uppercase tracking-wide">Backend Health</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="flex h-3 w-full overflow-hidden rounded-full bg-muted/20">
            {segments.map((s, i) => {
              const width = total > 0 ? (s.count / total) * 100 : 0
              if (width === 0) return null
              return (
                <div 
                  key={i} 
                  className={cn("h-full transition-all duration-500", 
                    s.variant === 'success' ? 'bg-[hsl(var(--success))]' : 
                    s.variant === 'warning' ? 'bg-[hsl(var(--warning))]' : 
                    'bg-[hsl(var(--destructive))]'
                  )} 
                  style={{ width: `${width}%` }} 
                />
              )
            })}
          </div>
          <div className="flex flex-wrap gap-8">
            {segments.map((s, i) => (
              <div key={i} className="flex items-center gap-2.5">
                <div className={cn("w-3 h-3 rounded-full shadow-sm", 
                   s.variant === 'success' ? 'bg-[hsl(var(--success))]' : 
                   s.variant === 'warning' ? 'bg-[hsl(var(--warning))]' : 
                   'bg-[hsl(var(--destructive))]'
                )} />
                <span className="text-sm font-bold tabular-nums">{s.count}</span>
                <span className="text-sm text-muted-foreground font-medium">{s.label}</span>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

// Adapted from Traefik Log Dashboard
function ResourceGauge({ label, percentage, icon: Icon, details, color }: {
  label: string;
  percentage: number;
  icon: any;
  details: { label: string; value: string }[];
  color: string;
}) {
  const data = [{ name: label, value: percentage, fill: color }];

  return (
    <Card className="hover:shadow-md transition-shadow">
      <CardContent className="p-4">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <Icon className="h-4 w-4" style={{ color }} />
            <span className="text-sm font-semibold uppercase tracking-wide">{label}</span>
          </div>
          <Badge variant={percentage < 50 ? 'success' : percentage < 75 ? 'warning' : 'destructive'} className="text-[10px] px-1.5 py-0">
            {percentage < 50 ? 'Normal' : percentage < 75 ? 'Moderate' : 'High'}
          </Badge>
        </div>
        <div className="flex items-center gap-4">
          <div className="h-24 w-24 shrink-0 relative">
            <ResponsiveContainer width="100%" height="100%">
              <RadialBarChart
                cx="50%"
                cy="50%"
                innerRadius="65%"
                outerRadius="100%"
                startAngle={180}
                endAngle={0}
                data={data}
                barSize={10}
              >
                <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
                <RadialBar
                  dataKey="value"
                  cornerRadius={5}
                  background={{ fill: 'hsl(var(--muted))' }}
                />
              </RadialBarChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex items-center justify-center pt-4">
              <span className="text-lg font-bold" style={{ color }}>
                {percentage.toFixed(0)}%
              </span>
            </div>
          </div>
          <div className="flex-1 space-y-1.5 min-w-0">
            {details.map((detail) => (
              <div key={detail.label} className="flex justify-between text-[10px]">
                <span className="text-muted-foreground truncate mr-2">{detail.label}</span>
                <span className="font-medium tabular-nums shrink-0">{detail.value}</span>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function getResourceColor(percentage: number): string {
  if (percentage < 50) return 'hsl(var(--success))';
  if (percentage < 75) return 'hsl(var(--warning))';
  return 'hsl(var(--destructive))';
}

export default function TraefikDashboardPage() {
  const [dashboardRange, setDashboardRange] = useState<DashboardRange>('1h')
  const { query } = useSearch()
  
  const [isLiveView, setIsLiveView] = useState(false)

  // Logs Config
  const tailLines = '100'
  const [isStreaming, setIsStreaming] = useState(false)
  const [streamLogs, setStreamLogs] = useState<string[]>([])
  const wsRef = useRef<WebSocket | null>(null)

  const stopStream = useCallback(() => {
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null }
    setIsStreaming(false)
  }, [])

  const logProcessing = useLogProcessingControl({ onDisabled: stopStream })
  const logProcessingEnabled = logProcessing.enabled

  // Dashboard Metrics
  const { data: dashboardData, isLoading: dashboardLoading } = useQuery({
    queryKey: ['logs-dashboard', 'traefik', dashboardRange],
    queryFn: async () => (await dashboardAPI.getTraefik(dashboardRange)).data.data,
    enabled: logProcessingEnabled,
    refetchInterval: () => logProcessingEnabled && isLiveView ? 5_000 : false,
    staleTime: isLiveView ? 3_000 : Infinity,
    gcTime: isLiveView ? 60_000 : 5 * 60_000,
  })
  
  const { data: traefikLogs } = useQuery({
    queryKey: ['logs-traefik', tailLines],
    queryFn: async () => (await api.logs.getTraefik(tailLines)).data.data ?? null,
    enabled: logProcessingEnabled && !isStreaming,
  })

  useMountEffect(() => stopStream)

  // ... (Implementing logic for Logs tab ...)
  const startWebSocket = useCallback(() => {
    if (!logProcessingEnabled) {
      toast.info('Log processing is disabled')
      return
    }
    const wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}${api.logs.getStreamUrl('traefik')}`
    try {
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws
      ws.onopen = () => { toast.success('Traefik log stream connected'); setStreamLogs([]) }
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
      toast.error(getErrorMessage(error, 'Failed to connect to stream', ErrorContexts.LogsStreamConnect))
      setIsStreaming(false)
    }
  }, [logProcessingEnabled])

  const handleToggleStream = useCallback(() => {
    if (isStreaming) {
      stopStream()
      // Note: We don't clear streamLogs here so the user can still see them, 
      // but they will be replaced by fetched logs when next refreshing.
    } else {
      if (!logProcessingEnabled) {
        toast.info('Log processing is disabled')
        return
      }
      setStreamLogs([])
      startWebSocket()
      setIsStreaming(true)
    }
  }, [isStreaming, logProcessingEnabled, startWebSocket, stopStream])

  const rawLogs = logProcessingEnabled ? (isStreaming ? streamLogs.join('\n') : traefikLogs?.logs || '') : ''
  
  const [levelFilter, setLevelFilter] = useState('all')
  const [selectedLog, setSelectedLog] = useState<any>(null)
  const [sortConfig, setSortConfig] = useState<{ key: string, direction: 'asc' | 'desc' }>({ key: 't', direction: 'desc' })

  const parsedLogs = useMemo(() => {
    if (!rawLogs) return []
    const lines = rawLogs.split('\n').filter(l => l.trim())
    return lines.map(parseTraefikLog)
  }, [rawLogs])

  const filteredLogs = useMemo(() => {
    let logs = [...parsedLogs] // Clone to sort
    
    if (levelFilter !== 'all') {
      logs = logs.filter(log => {
        if (levelFilter === 'error') return (log.status || 0) >= 400
        if (levelFilter === 'success') return (log.status || 0) >= 200 && (log.status || 0) < 400
        return true
      })
    }
    
    if (query) {
      const lower = query.toLowerCase()
      logs = logs.filter(log => 
        (log.path?.toLowerCase().includes(lower)) || 
        (log.ip?.toLowerCase().includes(lower)) ||
        (log.service?.toLowerCase().includes(lower)) ||
        (log.msg?.toLowerCase().includes(lower))
      )
    }

    // Sort
    logs.sort((a, b) => {
      let aVal = a[sortConfig.key] ?? ''
      let bVal = b[sortConfig.key] ?? ''
      
      // Numeric sort if applicable
      if (!isNaN(Number(aVal)) && !isNaN(Number(bVal)) && aVal !== '' && bVal !== '') {
        return sortConfig.direction === 'asc' ? Number(aVal) - Number(bVal) : Number(bVal) - Number(aVal)
      }

      if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1
      if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1
      return 0
    })

    return logs
  }, [parsedLogs, query, levelFilter, sortConfig])

  const toggleSort = (key: string) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'desc' ? 'asc' : 'desc'
    }))
  }

  // Data processing for charts
  const d = logProcessingEnabled ? dashboardData : undefined
  const slowestEndpoints = d?.slowest_endpoints ?? []
  
  const uaMetrics = useMemo(() => {
    const browserMap: Record<string, number> = {}
    const osMap: Record<string, number> = {}
    const cpuMap: Record<string, number> = {}
    const deviceMap: Record<string, number> = {}

    d?.user_agents?.forEach(ua => {
      const info = parseUserAgent(ua.name)
      browserMap[info.browser] = (browserMap[info.browser] || 0) + ua.value
      osMap[info.os] = (osMap[info.os] || 0) + ua.value
      cpuMap[info.cpu] = (cpuMap[info.cpu] || 0) + ua.value
      deviceMap[info.device] = (deviceMap[info.device] || 0) + ua.value
    })

    const toArr = (map: Record<string, number>) => 
      Object.entries(map).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value)

    return {
      browsers: toArr(browserMap),
      os: toArr(osMap),
      cpu: toArr(cpuMap),
      devices: toArr(deviceMap)
    }
  }, [d?.user_agents])

  const seriesData = useMemo(() => (d?.series ?? []).map((b: any) => {
    const t = new Date(b.t)
    const HHmm = b.t.slice(11, 16)
    const MMdd = `${t.getMonth() + 1}/${t.getDate()}`
    
    let dateStr = ''
    if (dashboardRange === '5m' || dashboardRange === '1h') {
      dateStr = b.t.slice(11, 19)
    } else if (dashboardRange === '6h' || dashboardRange === '24h') {
      dateStr = HHmm
    } else {
      // 7d or all - use MM/DD and HH:mm if not exactly at midnight
      if (HHmm === '00:00') {
        dateStr = MMdd
      } else {
        dateStr = `${MMdd} ${HHmm}`
      }
    }
    
    return {
      date: dateStr,
      Total: b.total,
      '2xx': b.c2xx,
      '3xx': b.c3xx,
      '4xx': b.c4xx,
      '5xx': b.c5xx,
      value: b.total,
    }
  }), [d?.series, dashboardRange])

  const seriesTickFormatter = useCallback((val: string) => {
    if (!val) return val
    if (val.includes(' ')) {
      // For MM/DD HH:mm, show only Date if it's a long range, otherwise show Time
      const parts = val.split(' ')
      if (dashboardRange === '7d' || dashboardRange === 'all') {
        return parts[0] // MM/DD
      }
      return parts[1] // HH:mm
    }
    return val
  }, [dashboardRange])

  const mapPoints = useMemo(() => (d?.top_ips ?? [])
    .filter((ip) => typeof ip.lat === 'number' && typeof ip.lng === 'number')
    .map((ip) => ({
      lat: ip.lat as number,
      lng: ip.lng as number,
      value: ip.count,
      label: `${ip.ip}${ip.country ? ` (${ip.country})` : ''}`,
      country: ip.country,
    })), [d?.top_ips])

  const groupedStatusCodes = useMemo(() => groupStatusCodes(d?.status_codes || []), [d?.status_codes])

  return (
    <div className="space-y-6">
      <PageHeader
        title="Traefik Dashboard"
        description="Comprehensive analytics and logs for your Traefik integration"
        breadcrumbs="Getting started / Traefik"
      />

      <LogProcessingToggle control={logProcessing} />

      {!logProcessingEnabled && (
        <Card>
          <CardContent className="py-6 text-sm text-muted-foreground">
            Log processing is disabled. Enable it to read Traefik logs, dashboard metrics, and live streams.
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="overview" className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 bg-card p-2 rounded-lg border">
          <TabsList className="bg-transparent flex-wrap h-auto justify-start">
            <TabsTrigger value="overview" className="gap-2 data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
              <LayoutDashboard className="h-4 w-4" /> Overview
            </TabsTrigger>
            <TabsTrigger value="traffic" className="gap-2 data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
              <Route className="h-4 w-4" /> Traffic
            </TabsTrigger>
            <TabsTrigger value="clients" className="gap-2 data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
              <Users className="h-4 w-4" /> Clients
            </TabsTrigger>
            <TabsTrigger value="geography" className="gap-2 data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
              <Globe className="h-4 w-4" /> Geography
            </TabsTrigger>
            <TabsTrigger value="system" className="gap-2 data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
              <Cpu className="h-4 w-4" /> System
            </TabsTrigger>
            <TabsTrigger value="logs" className="gap-2 data-[state=active]:bg-primary/10 data-[state=active]:text-primary">
              <FileText className="h-4 w-4" /> Logs
            </TabsTrigger>
          </TabsList>
          
          <div className="flex items-center gap-2">
            <Button variant={isLiveView ? "default" : "outline"} size="sm" onClick={() => setIsLiveView(!isLiveView)} disabled={!logProcessingEnabled} className="h-9 gap-2">
              <Activity className={cn("h-4 w-4", isLiveView && "animate-pulse")} />
              {isLiveView ? "Live" : "Static"}
            </Button>
            <RangeSelector value={dashboardRange} onChange={setDashboardRange} />
          </div>
        </div>

        {/* OVERVIEW TAB */}
        <TabsContent value="overview" className="space-y-6">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard 
              title="Total Requests" 
              value={dashboardLoading ? '—' : formatNumber(d?.total_requests ?? 0)} 
              description={d?.total_requests ? (() => {
                const sec = { '5m': 300, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800 }[d.range as string] || 3600;
                return `${(d.total_requests / sec).toFixed(2)} req/s`;
              })() : undefined}
              icon={<Activity className="h-4 w-4 text-[#3b82f6]" />} 
              loading={dashboardLoading} 
            />
            <StatCard 
              title="Avg Response Time" 
              value={dashboardLoading ? '—' : formatDuration(d?.avg_duration_ms)} 
              valueClassName={!d?.avg_duration_ms ? '' : d.avg_duration_ms < 100 ? 'text-[hsl(var(--success))]' : d.avg_duration_ms < 500 ? 'text-[hsl(var(--warning))]' : 'text-[hsl(var(--destructive))]'}
              description={d?.p99_response_time_ms != null ? <span className={d.p99_response_time_ms < 100 ? 'text-[hsl(var(--success))]' : d.p99_response_time_ms < 500 ? 'text-[hsl(var(--warning))]' : 'text-[hsl(var(--destructive))]'}>P99: {formatDuration(d.p99_response_time_ms)}</span> : undefined}
              icon={<Clock className="h-4 w-4" />} 
              loading={dashboardLoading} 
            />
            <StatCard 
              title="Success Rate" 
              value={dashboardLoading ? '—' : formatPercent(1 - (d?.error_rate ?? 0))} 
              description={d?.error_rate != null ? `Error Rate: ${formatPercent(d.error_rate)}` : undefined}
              valueClassName={(1 - (d?.error_rate ?? 0)) >= 0.95 ? 'text-[hsl(var(--success))]' : (1 - (d?.error_rate ?? 0)) >= 0.90 ? 'text-[hsl(var(--warning))]' : 'text-[hsl(var(--destructive))]'}
              icon={<TrendingUp className="h-4 w-4" />} 
              loading={dashboardLoading} 
            />
            <StatCard 
              title="Unique IPs" 
              value={dashboardLoading ? '—' : formatNumber(d?.unique_ips ?? 0)} 
              description="Unique clients"
              icon={<Users className="h-4 w-4" />} 
              loading={dashboardLoading} 
            />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="hover:shadow-md transition-shadow lg:col-span-2">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold uppercase tracking-wide">
                  Request Volume
                </CardTitle>
              </CardHeader>
              <CardContent>
                {seriesData.length > 0 ? (
                  <AreaTimeline data={seriesData} dataKey="Total" xAxisKey="date" height={280} tickFormatter={seriesTickFormatter} />
                ) : <div className="py-12 text-center text-sm text-muted-foreground">No requests in range</div>}
              </CardContent>
            </Card>

            <Card className="hover:shadow-md transition-shadow flex flex-col">
              <CardHeader className="pb-2 bg-transparent border-b-0">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-semibold uppercase tracking-wide"> 
                    Active Signals
                  </CardTitle>
                  <Badge variant="outline" className="text-xs tabular-nums">
                    {Math.min((d?.recent_errors?.length || 0), 5)}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="p-4 flex-1">
                {!(d?.recent_errors?.length) ? (
                  <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                    <div className="w-10 h-10 rounded-full bg-success/20 flex items-center justify-center mb-3">
                      <Zap className="h-5 w-5 text-success" />
                    </div>
                    <p className="text-sm">All systems normal</p>
                  </div>
                ) : (
                  <div className="space-y-3 max-h-[220px] overflow-auto">
                      {(d?.recent_errors || []).slice(0, 5).map((error: any, idx: number) => {
                        const isCritical = error.status >= 500;
                        const dot = isCritical ? 'bg-destructive' : 'bg-warning';
                        const time = new Date(error.t).toLocaleTimeString();
                        return (
                          <div key={idx} className="flex items-start gap-3">      
                            <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${dot}`} />
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium leading-tight truncate">{error.path || 'Unknown path'}</p>
                              <p className="text-xs text-muted-foreground mt-0.5">{error.status} {error.method} error detected</p>
                              <p className="text-xs text-muted-foreground mt-0.5 flex items-center gap-1">
                                  <Clock className="h-3 w-3" />
                                  {time}
                              </p>
                            </div>
                          </div>
                        );
                      })}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
          
          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="hover:shadow-md transition-shadow">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold uppercase tracking-wide">   
                  Status Code Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-col sm:flex-row items-center gap-6 w-full">
                  <div className="h-48 w-48 shrink-0">  
                    {groupedStatusCodes.length ? <PieBreakdown data={groupedStatusCodes} 
                      height={192} 
                      innerRadius={55} 
                      outerRadius={75} 
                      showLegend={false}
                     /> : <div className="py-12 text-center text-sm text-muted-foreground">No data</div>}
                  </div>
                  <div className="flex-1 space-y-3">
                    {[
                      { label: '2xx Success', name: '2xx', color: 'bg-[hsl(var(--success))]' },
                      { label: '3xx Redirect', name: '3xx', color: 'bg-[hsl(var(--info))]' },
                      { label: '4xx Client Error', name: '4xx', color: 'bg-[hsl(var(--warning))]' },
                      { label: '5xx Server Error', name: '5xx', color: 'bg-[hsl(var(--destructive))]' },
                    ].map((item) => {
                      const val = groupedStatusCodes.find(x => x.name === item.name)?.value || 0;
                      const tot = d?.total_requests || 1;
                      const pct = d?.total_requests ? ((val / tot) * 100).toFixed(1) : '0.0';
                      return (
                        <div key={item.label} className="flex items-center gap-3 text-sm">
                          <div className={`w-2.5 h-2.5 rounded-full ${item.color} shrink-0`} />
                          <span className="text-muted-foreground flex-1">{item.label}</span>
                          <span className="font-semibold tabular-nums">{formatNumber(val)}</span>
                          <span className="text-muted-foreground tabular-nums w-12 text-right">{pct}%</span>
                        </div>
                      );
                    })}
                    <div className="pt-3 border-t flex items-center justify-between">   
                      <span className="text-sm text-muted-foreground">Error Rate</span> 
                      <span className={`text-lg font-bold tabular-nums ${(d?.error_rate || 0) > 0.05 ? 'text-[hsl(var(--destructive))]' : 'text-[hsl(var(--success))]'}`}>
                        {((d?.error_rate || 0) * 100).toFixed(2)}%
                      </span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="hover:shadow-md transition-shadow">
              <CardHeader className="pb-2 bg-transparent border-b-0">
                <CardTitle className="text-sm font-semibold uppercase tracking-wide">   
                  Response Time Percentiles
                </CardTitle>
                {!d?.avg_duration_ms && (
                  <p className="text-xs text-muted-foreground mt-1 tracking-normal">
                    Duration is unavailable for this interval.
                  </p>
                )}
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-3 gap-2 py-4">
                  {[
                    { label: 'Average', desc: 'Mean response time', val: d?.avg_duration_ms },
                    { label: 'P95', desc: '95% of requests', val: d?.p95_response_time_ms },
                    { label: 'P99', desc: '99% of requests', val: d?.p99_response_time_ms }
                  ].map(m => {
                    const noData = m.val == null || m.val === 0;
                    const value = m.val || 0;
                    const color = noData ? 'hsl(var(--muted-foreground))' : value < 100 ? 'hsl(var(--success))' : value < 500 ? 'hsl(var(--warning))' : 'hsl(var(--destructive))';
                    const textColor = noData ? 'text-muted-foreground' : value < 100 ? 'text-[hsl(var(--success))]' : value < 500 ? 'text-[hsl(var(--warning))]' : 'text-[hsl(var(--destructive))]';
                    const pct = noData ? 0 : Math.min((value / 2000) * 100, 100);
                    return (
                      <div key={m.label} className="flex flex-col items-center">
                        <div className="relative h-28 w-28 flex items-center justify-center">
                          <svg viewBox="0 0 100 100" className="w-full h-full">
                            <path d="M 10 50 A 40 40 0 0 1 90 50" fill="none" stroke="currentColor" strokeWidth="8" className="text-muted/20" strokeLinecap="round" />
                            {!noData && <path d="M 10 50 A 40 40 0 0 1 90 50" fill="none" stroke={color} strokeWidth="8" strokeDasharray="125.6" strokeDashoffset={125.6 - (pct / 100) * 125.6} strokeLinecap="round" />}
                          </svg>
                          <div className={`absolute top-1/2 left-1/2 -translate-x-1/2 translate-y-0 text-center font-bold text-xl ${textColor}`}>
                            {noData ? 'N/A' : <>
                              <span style={{ color }}>{value.toFixed(0)}</span><span className="text-xs" style={{ color: 'hsl(var(--muted-foreground))' }}>ms</span>
                            </>}
                          </div>
                        </div>
                        <div className="text-center -mt-4">
                          <p className="text-sm font-semibold">{m.label}</p>
                          <p className="text-xs text-muted-foreground">{m.desc}</p>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </CardContent>
            </Card>
          </div>

          <Card className="hover:shadow-md transition-shadow">
            <CardHeader className="pb-2 bg-transparent border-b-0">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-2">
                    {isLiveView ? (
                      <>
                        <div className="relative">
                          <div className="w-2 h-2 bg-[hsl(var(--success))] rounded-full" />
                          <div className="absolute inset-0 w-2 h-2 bg-[hsl(var(--success))] rounded-full animate-ping opacity-75" />
                        </div>
                        <span className="text-xs font-semibold uppercase text-[hsl(var(--success))]">Live</span>
                      </>
                    ) : (
                      <>
                        <div className="w-2 h-2 bg-muted-foreground/50 rounded-full" />
                        <span className="text-xs font-semibold uppercase text-muted-foreground">Static</span>
                      </>
                    )}
                  </div>
                  <CardTitle className="text-sm font-semibold uppercase tracking-wide"> 
                    Event Feed
                  </CardTitle>
                </div>
              </div>
            </CardHeader>
            <CardContent className="p-0 max-h-[450px] overflow-auto">
              {rawLogs && rawLogs.trim() ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="bg-muted/50 text-xs text-muted-foreground sticky top-0 backdrop-blur z-10">
                      <tr>
                        <th className="px-4 py-2 font-medium text-left">Time</th>
                        <th className="px-4 py-2 font-medium text-left">Method</th>
                        <th className="px-4 py-2 font-medium text-left">Path</th>
                        <th className="px-4 py-2 font-medium text-left">Status</th>
                        <th className="px-4 py-2 font-medium text-right">Duration</th>
                        <th className="px-4 py-2 font-medium text-left">Service</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rawLogs.split('\n').filter(l => l.trim()).slice(-20).reverse().map((line, i) => {
                        const parsed = parseTraefikLog(line)
                        const time = parsed.t ? (typeof parsed.t === 'string' && parsed.t.includes('T') ? new Date(parsed.t).toLocaleTimeString() : parsed.t) : '—'
                        
                        if (!parsed.method && !parsed.status) {
                          const isError = line.includes('level=error') || line.match(/"status":\s*5\d\d/);
                          const isWarn = line.includes('level=warn') || line.match(/"status":\s*4\d\d/);
                          const color = isError ? 'bg-[hsl(var(--destructive))]' : isWarn ? 'bg-[hsl(var(--warning))]' : 'bg-[hsl(var(--success))]';
                          return (
                            <tr key={i} className="border-t hover:bg-muted/30 transition-colors">
                              <td colSpan={6} className="px-4 py-2 text-xs font-mono">
                                <div className="flex items-center gap-3">
                                   <div className={`w-1.5 h-1.5 rounded-full ${color} shrink-0`}></div>
                                   <div className="truncate flex-1" title={line}>{line}</div>
                                </div>
                              </td>
                            </tr>
                          );
                        }

                        return (
                          <tr key={i} className="border-t hover:bg-muted/30 transition-colors">
                            <td className="px-4 py-2 text-[11px] text-muted-foreground whitespace-nowrap font-mono">{time}</td>
                            <td className="px-4 py-2">
                              {parsed.method ? (
                                <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px] font-bold border", getMethodStyles(String(parsed.method)))}>
                                  {parsed.method}
                                </Badge>
                              ) : '—'}
                            </td>
                            <td className="px-4 py-2 text-[11px] font-mono truncate max-w-[200px]" title={String(parsed.path || '')}>{parsed.path || '—'}</td>
                            <td className="px-4 py-2">
                              {parsed.status ? (
                                <Badge variant={getStatusVariant(Number(parsed.status))} className="px-1.5 py-0 text-[10px] font-bold">
                                  {parsed.status}
                                </Badge>
                              ) : '—'}
                            </td>
                            <td className="px-4 py-2 text-[11px] font-mono text-muted-foreground text-right">
                              {parsed.duration != null ? formatDuration(Number(parsed.duration)) : '—'}
                            </td>
                            <td className="px-4 py-2 text-[11px] font-mono text-muted-foreground truncate max-w-[150px]" title={String(parsed.service || '')}>
                              {parsed.service || '—'}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-12 text-sm text-muted-foreground">
                  <Zap className="h-6 w-6 mb-2 opacity-50" />
                  Waiting for events...
                </div>
              )}
            </CardContent>
          </Card>

        </TabsContent>

        {/* TRAFFIC TAB */}
        <TabsContent value="traffic" className="space-y-6 min-w-0">
          {/* Traffic Health */}
          <HealthBar 
            segments={[
              { label: 'Healthy', count: d?.top_services?.filter(s => s.error_rate < 5).length || 0, variant: 'success' },
              { label: 'Warning', count: d?.top_services?.filter(s => s.error_rate >= 5 && s.error_rate < 10).length || 0, variant: 'warning' },
              { label: 'Critical', count: d?.top_services?.filter(s => s.error_rate >= 10).length || 0, variant: 'destructive' },
            ]}
          />

          <div className="grid gap-6 lg:grid-cols-2 min-w-0">
            {/* Top Routes */}
            <Card className="hover:shadow-md transition-shadow min-w-0">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-semibold uppercase tracking-wide">Top Routes</CardTitle>
                <Route className="h-5 w-5 text-primary" />
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-80 pr-4">
                  <div className="space-y-1">
                    {d?.top_paths?.length ? (
                      (() => {
                        const maxCount = Math.max(...d.top_paths.map((r: any) => r.count), 1);
                        return d.top_paths.slice(0, 15).map((route: any, idx: number) => {
                          const barWidth = (route.count / maxCount) * 100;
                          return (
                            <div key={idx} className="relative flex items-center gap-3 px-3 py-2 rounded-md hover:bg-muted/50 transition-colors group">
                              <div
                                className="absolute inset-y-0 left-0 bg-primary/5 rounded-md transition-all duration-500"
                                style={{ width: `${barWidth}%` }}
                              />
                              <div className="relative flex items-center gap-2 flex-1 min-w-0">
                                {route.method && (
                                  <Badge variant="outline" className={cn("text-[10px] px-1.5 py-0 shrink-0 font-bold border", getMethodStyles(route.method))}>
                                    {route.method}
                                  </Badge>
                                )}
                                <span className="font-mono text-xs truncate text-muted-foreground group-hover:text-foreground transition-colors" title={route.path}>
                                  {route.path}
                                </span>
                              </div>
                              <div className="relative text-right shrink-0">
                                <span className="text-sm font-semibold tabular-nums">{route.count.toLocaleString()}</span>
                                <p className="text-[10px] text-muted-foreground">{route.avg_duration_ms.toFixed(0)}ms</p>
                              </div>
                            </div>
                          );
                        });
                      })()
                    ) : (
                      <div className="py-12 text-center text-sm text-muted-foreground flex flex-col items-center gap-2">
                        <Route className="h-6 w-6 opacity-20" />
                        No route data available
                      </div>
                    )}
                  </div>
                </ScrollArea>
                {(d?.top_paths?.length || 0) > 15 && (
                  <p className="text-[10px] text-muted-foreground text-center pt-2 italic">
                    Showing top 15 of {d?.top_paths?.length ?? 0} routes
                  </p>
                )}
              </CardContent>
            </Card>

            {/* Top Services */}
            <Card className="hover:shadow-md transition-shadow min-w-0">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-semibold uppercase tracking-wide">Top Services</CardTitle>
                <Server className="h-5 w-5 text-primary" />
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-80 pr-4">
                  <div className="space-y-1">
                    {d?.top_services?.length ? (
                      (() => {
                        const maxCount = Math.max(...d.top_services.map((s: any) => s.requests), 1);
                        return d.top_services.slice(0, 15).map((service: any, idx: number) => {
                          const barWidth = (service.requests / maxCount) * 100;
                          const variant = service.error_rate < 5 ? 'success' : service.error_rate < 10 ? 'warning' : 'destructive';
                          return (
                            <div key={idx} className="relative flex items-center gap-3 px-3 py-2 rounded-md hover:bg-muted/50 transition-colors group">
                              <div
                                className="absolute inset-y-0 left-0 bg-primary/5 rounded-md transition-all duration-500"
                                style={{ width: `${barWidth}%` }}
                              />
                              <div className={cn("relative w-1 h-8 rounded-full shrink-0", 
                                variant === 'success' ? 'bg-[hsl(var(--success))]' : 
                                variant === 'warning' ? 'bg-[hsl(var(--warning))]' : 
                                'bg-[hsl(var(--destructive))]'
                              )} />
                              <div className="relative flex-1 min-w-0">
                                <span className="text-sm font-medium truncate block text-muted-foreground group-hover:text-foreground transition-colors" title={service.name}>
                                  {service.name}
                                </span>
                                <div className="flex items-center gap-3 text-[10px] text-muted-foreground/70">
                                  <span className="flex items-center gap-1"><Clock className="h-2.5 w-2.5" />{service.avg_duration_ms.toFixed(0)}ms avg</span>
                                  <span className={service.error_rate > 5 ? 'text-destructive font-medium' : ''}>
                                    {service.error_rate.toFixed(1)}% error
                                  </span>
                                </div>
                              </div>
                              <span className="relative text-sm font-semibold tabular-nums shrink-0">
                                {service.requests.toLocaleString()}
                              </span>
                            </div>
                          );
                        });
                      })()
                    ) : (
                      <div className="py-12 text-center text-sm text-muted-foreground flex flex-col items-center gap-2">
                        <Server className="h-6 w-6 opacity-20" />
                        No service data available
                      </div>
                    )}
                  </div>
                </ScrollArea>
                {(d?.top_services?.length || 0) > 15 && (
                  <p className="text-[10px] text-muted-foreground text-center pt-2 italic">
                    Showing top 15 of {d?.top_services?.length ?? 0} services
                  </p>
                )}
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-6 lg:grid-cols-2 min-w-0">
            <Card className="hover:shadow-md transition-shadow min-w-0">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold uppercase tracking-wide">HTTP Methods</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-col sm:flex-row items-center gap-6 w-full">
                  <div className="h-48 w-48 shrink-0">
                    {d?.methods?.length ? (
                      <PieBreakdown data={d.methods} height={192} innerRadius={55} outerRadius={75} showLegend={false} />
                    ) : <div className="py-12 text-center text-sm text-muted-foreground">No data</div>}
                  </div>
                  <div className="flex-1 space-y-2">
                    {(d?.methods || []).slice(0, 5).map((m, idx) => (
                      <div key={idx} className="flex items-center gap-3 text-sm">
                        <div className={cn("w-2 h-2 rounded-full shrink-0", 
                          m.name === 'GET' ? "bg-[hsl(var(--success))]" :
                          m.name === 'POST' ? "bg-[hsl(var(--info))]" :
                          m.name === 'PUT' ? "bg-[hsl(var(--warning))]" :
                          m.name === 'DELETE' ? "bg-[hsl(var(--destructive))]" :
                          "bg-muted"
                        )} />
                        <span className="flex-1 truncate font-medium text-muted-foreground">{m.name}</span>
                        <span className="font-bold tabular-nums">{m.value.toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="hover:shadow-md transition-shadow min-w-0">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-semibold uppercase tracking-wide">TLS Versions</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-col sm:flex-row items-center gap-6 w-full">
                  <div className="h-48 w-48 shrink-0">
                    {d?.tls_versions?.length ? (
                      <PieBreakdown data={d.tls_versions} height={192} innerRadius={55} outerRadius={75} showLegend={false} />
                    ) : <div className="py-12 text-center text-sm text-muted-foreground">No data</div>}
                  </div>
                  <div className="flex-1 space-y-2">
                    {(d?.tls_versions || []).slice(0, 5).map((v, idx) => (
                      <div key={idx} className="flex items-center gap-3 text-sm">
                        <div className="w-2 h-2 rounded-full bg-primary/40 shrink-0" />
                        <span className="flex-1 truncate font-medium text-muted-foreground">{v.name}</span>
                        <span className="font-bold tabular-nums">{v.value.toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-6 lg:grid-cols-2 min-w-0">
            {/* Backend Services Detail */}
            <Card className="hover:shadow-md transition-shadow min-w-0">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-semibold uppercase tracking-wide">Backend Services Detail</CardTitle>
                <Server className="h-5 w-5 text-muted-foreground opacity-50" />
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-[400px] overflow-y-auto pr-2">
                  {d?.top_services?.length ? (
                    d.top_services.map((s, i) => {
                      const variant = s.error_rate < 5 ? 'success' : s.error_rate < 10 ? 'warning' : 'destructive';
                      const totalRequests = d.total_requests || 1;
                      const percentage = (s.requests / totalRequests) * 100;
                      return (
                        <div key={i} className="flex items-center gap-3 p-3 rounded-lg border bg-muted/5 hover:bg-muted/20 transition-colors">
                          <div className={cn("w-1 self-stretch rounded-full shrink-0", 
                            variant === 'success' ? 'bg-[hsl(var(--success))]' : 
                            variant === 'warning' ? 'bg-[hsl(var(--warning))]' : 
                            'bg-[hsl(var(--destructive))]'
                          )} />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-0.5">
                              <span className="font-bold text-sm truncate font-mono" title={s.name}>{s.name}</span>
                              <Badge variant={variant === 'destructive' ? 'destructive' : variant === 'success' ? 'success' : 'warning'} className="text-[10px] px-1 py-0 h-4">
                                {s.error_rate < 5 ? 'Healthy' : s.error_rate < 10 ? 'Warning' : 'Critical'}
                              </Badge>
                            </div>
                            <div className="flex items-center gap-3 text-[10px] text-muted-foreground font-medium">
                              <span className="flex items-center gap-1"><Clock className="h-2.5 w-2.5" />{s.avg_duration_ms.toFixed(0)}ms avg</span>
                              <span className={s.error_rate > 5 ? 'text-destructive' : ''}>
                                {s.error_rate.toFixed(1)}% error
                              </span>
                            </div>
                          </div>
                          <div className="text-right shrink-0">
                            <div className="text-sm font-bold tabular-nums">{s.requests.toLocaleString()}</div>
                            <div className="text-[10px] text-muted-foreground">{percentage.toFixed(1)}%</div>
                          </div>
                        </div>
                      )
                    })
                  ) : (
                    <div className="py-12 text-center text-sm text-muted-foreground">No service details available</div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Routers */}
            <Card className="hover:shadow-md transition-shadow min-w-0">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-semibold uppercase tracking-wide">Routers</CardTitle>
                <Activity className="h-5 w-5 text-primary" />
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-80 pr-4">
                  <div className="space-y-1">
                    {d?.top_routers?.length ? (
                      (() => {
                        const maxCount = Math.max(...d.top_routers.map((r: any) => r.requests), 1);
                        return d.top_routers.map((router: any, idx: number) => {
                          const barWidth = (router.requests / maxCount) * 100;
                          return (
                            <div key={idx} className="relative flex items-center gap-3 px-3 py-2 rounded-md hover:bg-muted/50 transition-colors group">
                              <div
                                className="absolute inset-y-0 left-0 bg-primary/5 rounded-md transition-all duration-500"
                                style={{ width: `${barWidth}%` }}
                              />
                              <div className="relative flex-1 min-w-0">
                                <span className="text-sm font-medium truncate block text-muted-foreground group-hover:text-foreground transition-colors" title={router.name}>
                                  {router.name}
                                </span>
                                {router.service && (
                                  <span className="text-[10px] text-muted-foreground/70">→ {router.service}</span>
                                )}
                              </div>
                              <div className="relative text-right shrink-0">
                                <span className="text-sm font-semibold tabular-nums">{router.requests.toLocaleString()}</span>
                                <p className="text-[10px] text-muted-foreground">{router.avg_duration_ms.toFixed(0)}ms</p>
                              </div>
                            </div>
                          );
                        });
                      })()
                    ) : (
                      <div className="py-12 text-center text-sm text-muted-foreground flex flex-col items-center gap-2">
                        <Activity className="h-6 w-6 opacity-20" />
                        No router data available
                      </div>
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </div>

          {d?.format !== 'json' && (
            <Card className="border-dashed">
              <CardContent className="py-4 text-center text-xs text-muted-foreground">
                <div className="flex flex-col sm:flex-row items-center justify-center gap-2">
                  <Zap className="h-3 w-3 shrink-0" />
                  <span className="max-w-full">Detailed Traffic metrics (Hosts, Services, Routers) require Traefik JSON access logs.</span>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* CLIENTS TAB */}
        <TabsContent value="clients" className="space-y-6">
          <Card className="hover:shadow-md transition-shadow">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold uppercase tracking-wide">Client Analysis</CardTitle>
              <CardDescription>Top sources and targets for your traffic</CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="ips" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="ips" className="gap-2">
                    <Users className="h-4 w-4" />
                    <span className="hidden sm:inline">Client IPs</span>
                    <span className="sm:hidden">IPs</span>
                  </TabsTrigger>
                  <TabsTrigger value="hosts" className="gap-2">
                    <Globe className="h-4 w-4" />
                    <span className="hidden sm:inline">Request Hosts</span>
                    <span className="sm:hidden">Hosts</span>
                  </TabsTrigger>
                  <TabsTrigger value="addresses" className="gap-2">
                    <Network className="h-4 w-4" />
                    <span className="hidden sm:inline">Target Addresses</span>
                    <span className="sm:hidden">Addr</span>
                  </TabsTrigger>
                </TabsList>
                <TabsContent value="ips" className="mt-4 pt-4">
                  {d?.top_ips?.length ? (
                    <BarDistribution 
                      data={d.top_ips.slice(0, 10).map(ip => ({ name: ip.ip, value: ip.count }))} 
                      layout="horizontal" 
                      height={320} 
                      color="hsl(var(--chart-1))" 
                    />
                  ) : (
                    <div className="py-12 text-center text-sm text-muted-foreground flex flex-col items-center gap-2">
                      <Users className="h-6 w-6 opacity-20" />
                      No client IP data available
                    </div>
                  )}
                </TabsContent>
                <TabsContent value="hosts" className="mt-4 pt-4">
                  {d?.top_hosts?.length ? (
                    <BarDistribution 
                      data={d.top_hosts} 
                      layout="horizontal" 
                      height={320} 
                      color="hsl(var(--chart-2))" 
                    />
                  ) : (
                    <div className="py-12 text-center text-sm text-muted-foreground flex flex-col items-center gap-2">
                      <Globe className="h-6 w-6 opacity-20" />
                      No host data available
                    </div>
                  )}
                </TabsContent>
                <TabsContent value="addresses" className="mt-4 pt-4">
                  {d?.top_addresses?.length ? (
                    <BarDistribution 
                      data={d.top_addresses} 
                      layout="horizontal" 
                      height={320} 
                      color="hsl(var(--chart-3))" 
                    />
                  ) : (
                    <div className="py-12 text-center text-sm text-muted-foreground flex flex-col items-center gap-2">
                      <Network className="h-6 w-6 opacity-20" />
                      No address data available
                    </div>
                  )}
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>

          {/* UA Breakdown Grid */}
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {[
              { title: 'Browsers', data: uaMetrics.browsers, icon: Monitor, color: 'hsl(var(--chart-1))' },
              { title: 'Operating Systems', data: uaMetrics.os, icon: Activity, color: 'hsl(var(--chart-2))' },
              { title: 'Processors', data: uaMetrics.cpu, icon: CpuIcon, color: 'hsl(var(--chart-3))' },
              { title: 'Devices', data: uaMetrics.devices, icon: Users, color: 'hsl(var(--chart-4))' },
            ].map((box, i) => (
              <Card key={i} className="hover:shadow-md transition-shadow">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1 pt-4">
                  <CardTitle className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">{box.title}</CardTitle>
                  <box.icon className="h-3.5 w-3.5 text-muted-foreground opacity-50" />
                </CardHeader>
                <CardContent className="pt-0">
                  {box.data.length ? (
                    <div className="space-y-4">
                      <div className="h-32 flex items-center justify-center pt-2">
                        <PieBreakdown 
                          data={box.data} 
                          height={120} 
                          innerRadius={35} 
                          outerRadius={50} 
                          showLegend={false} 
                        />
                      </div>
                      <div className="space-y-1.5 max-h-32 overflow-y-auto pr-1">
                        {box.data.slice(0, 5).map((item, idx) => (
                          <div key={idx} className="flex items-center justify-between text-[11px]">
                            <span className="truncate flex-1 text-muted-foreground font-medium pr-2" title={item.name}>{item.name}</span>
                            <span className="font-bold tabular-nums">{item.value.toLocaleString()}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="py-12 text-center text-[10px] text-muted-foreground italic">No data</div>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* GEOGRAPHY TAB */}
        <TabsContent value="geography" className="space-y-4">
          <ChartCard title="Top Client IPs" description="By request count">
            <div className="grid lg:grid-cols-2 gap-4">
              <div>
                {mapPoints.length > 0 ? <ThreatMap data={mapPoints} height={320} /> : <div className="py-12 text-center text-sm text-muted-foreground">No GeoIP data</div>}
              </div>
              <div className="overflow-auto rounded-md border h-[320px]">
                <table className="w-full text-sm">
                  <thead className="bg-muted text-xs uppercase text-muted-foreground sticky top-0">
                    <tr><th className="px-3 py-2 text-left">IP</th><th className="px-3 py-2 text-left">Country</th><th className="px-3 py-2 text-right">Requests</th></tr>
                  </thead>
                  <tbody>
                    {(d?.top_ips ?? []).slice(0, 15).map(row => (
                      <tr key={row.ip} className="border-t"><td className="px-3 py-1.5 font-mono">{row.ip}</td><td className="px-3 py-1.5">{row.country ?? '—'}</td><td className="px-3 py-1.5 text-right">{row.count.toLocaleString()}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </ChartCard>
        </TabsContent>

        {/* SYSTEM TAB */}
        <TabsContent value="system" className="space-y-6">
          {!d?.system ? (
            <Card className="hover:shadow-md transition-shadow">
              <CardContent className="flex items-center justify-center py-12 text-muted-foreground">
                <div className="text-center">
                  <Server className="h-12 w-12 mx-auto mb-4 opacity-20" />
                  <p className="text-sm">System statistics not available</p>
                  <p className="text-xs mt-1">Metrics collection requires Linux /proc interface</p>
                </div>
              </CardContent>
            </Card>
          ) : (
            <>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <ResourceGauge
                  label="CPU"
                  percentage={d.system.cpu.usage_percent}
                  icon={CpuIcon}
                  color={getResourceColor(d.system.cpu.usage_percent)}
                  details={[
                    { label: 'Cores', value: String(d.system.cpu.cores) },
                    { label: 'Model', value: d.system.cpu.model ? d.system.cpu.model.split('@')[0].trim() : 'Unknown' },
                  ]}
                />
                <ResourceGauge
                  label="Memory"
                  percentage={d.system.memory.used_percent}
                  icon={MemoryStick}
                  color={getResourceColor(d.system.memory.used_percent)}
                  details={[
                    { label: 'Used', value: formatBytes(d.system.memory.used) },
                    { label: 'Total', value: formatBytes(d.system.memory.total) },
                    { label: 'Free', value: formatBytes(d.system.memory.available) },
                  ]}
                />
                <ResourceGauge
                  label="Disk"
                  percentage={d.system.disk.used_percent}
                  icon={HardDrive}
                  color={getResourceColor(d.system.disk.used_percent)}
                  details={[
                    { label: 'Used', value: formatBytes(d.system.disk.used) },
                    { label: 'Total', value: formatBytes(d.system.disk.total) },
                    { label: 'Free', value: formatBytes(d.system.disk.free) },
                  ]}
                />
              </div>

              <HealthBar 
                segments={[
                  { label: 'Normal', count: [d.system.cpu.usage_percent, d.system.memory.used_percent, d.system.disk.used_percent].filter(p => p < 50).length, variant: 'success' },
                  { label: 'Moderate', count: [d.system.cpu.usage_percent, d.system.memory.used_percent, d.system.disk.used_percent].filter(p => p >= 50 && p < 75).length, variant: 'warning' },
                  { label: 'High', count: [d.system.cpu.usage_percent, d.system.memory.used_percent, d.system.disk.used_percent].filter(p => p >= 75).length, variant: 'destructive' },
                ]}
              />

              <div className="grid gap-6 lg:grid-cols-2 min-w-0">
                <div className="min-w-0">
                  <ChartCard title="Slowest Endpoints" description="Max latency per path (ms)">
                    {slowestEndpoints.length ? <BarDistribution data={slowestEndpoints} layout="horizontal" height={280} color="hsl(var(--chart-3))" /> : <div className="py-12 text-center text-muted-foreground">No data</div>}
                  </ChartCard>
                </div>
                <div className="min-w-0">
                  <ChartCard title="Recent Errors" description="Latest 4xx and 5xx responses">
                    <div className="overflow-auto max-h-[300px]">
                    <table className="w-full text-sm">
                      <thead className="bg-muted text-xs uppercase text-muted-foreground sticky top-0 z-10">
                        <tr><th className="px-3 py-2 text-left">Time</th><th className="px-3 py-2 text-left">Status</th><th className="px-3 py-2 text-left">IP</th><th className="px-3 py-2 text-left">Method</th><th className="px-3 py-2 text-left">Path</th></tr>
                      </thead>
                      <tbody>
                        {(d?.recent_errors ?? []).map((e, i) => (
                          <tr key={i} className="border-t hover:bg-muted/30 transition-colors">
                            <td className="px-3 py-1.5 whitespace-nowrap text-muted-foreground font-mono text-[11px]">{new Date(e.t).toLocaleTimeString()}</td>
                            <td className="px-3 py-1.5"><Badge variant={getStatusVariant(e.status)} className="px-1.5 py-0 text-[10px] font-bold">{e.status}</Badge></td>
                            <td className="px-3 py-1.5 font-mono text-xs">{e.ip}</td>
                            <td className="px-3 py-1.5">
                              <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px] font-bold border", getMethodStyles(e.method ?? ''))}>
                                {e.method ?? '—'}
                              </Badge>
                            </td>
                            <td className="px-3 py-1.5 font-mono text-xs truncate max-w-[200px]">{e.path ?? '—'}</td>
                          </tr>
                        ))}
                        {!(d?.recent_errors?.length) && <tr><td colSpan={5} className="py-6 text-center text-muted-foreground">No recent errors</td></tr>}
                      </tbody>
                    </table>
                  </div>
                </ChartCard>
                </div>
              </div>
            </>
          )}
        </TabsContent>

        {/* LOGS TAB */}
        <TabsContent value="logs" className="space-y-6 min-w-0">
          <div className="grid gap-6 min-w-0">
            {/* Recent Errors Card (Parity with traefik-log-dashboard) */}
            <Card className="hover:shadow-md transition-shadow min-w-0">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <div className="space-y-1">
                  <CardTitle className="text-sm font-semibold uppercase tracking-wide">Recent Traffic Errors</CardTitle>
                  <CardDescription>Latest 4xx and 5xx responses detected</CardDescription>
                </div>
                <AlertTriangle className="h-5 w-5 text-destructive" />
              </CardHeader>
              <CardContent>
                {!(d?.recent_errors?.length) ? (
                  <div className="py-6 text-center text-sm text-muted-foreground flex flex-col items-center gap-2">
                    <Check className="h-6 w-6 text-success opacity-50" />
                    No recent errors recorded
                  </div>
                ) : (
                  <div className="space-y-2 max-h-48 overflow-y-auto pr-2">
                    {d.recent_errors.slice(0, 10).map((error, idx) => (
                      <div key={idx} className="flex items-start gap-3 p-2.5 rounded-lg bg-destructive/5 border border-destructive/10 hover:bg-destructive/10 transition-colors">
                        <div className="w-1.5 h-1.5 rounded-full bg-destructive mt-1.5 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <Badge variant={getStatusVariant(error.status)} className="text-[10px] px-1.5 py-0 font-bold">
                              {error.status}
                            </Badge>
                            <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                              <Clock className="h-2.5 w-2.5" />
                              {new Date(error.t).toLocaleTimeString()}
                            </span>
                          </div>
                          <p className="text-xs font-mono text-foreground truncate">{error.path || 'Unknown error'}</p>
                        </div>
                        <Badge variant="outline" className="text-[9px] opacity-70">{error.method}</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Main Logs Table Card */}
            <Card className="hover:shadow-md transition-shadow min-w-0 overflow-hidden">
              <CardHeader className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b">
                <div className="flex items-center gap-3">
                  <CardTitle className="text-sm font-semibold uppercase tracking-wide">Live Traffic Logs</CardTitle>
                  <Badge variant="outline" className="text-xs tabular-nums bg-muted/50">
                    {parsedLogs.length} entries
                  </Badge>
                  <div className="flex items-center gap-1.5">
                    <div className="relative">
                      <div className={cn("w-2 h-2 rounded-full", isStreaming ? "bg-success" : "bg-muted-foreground/30")} />
                      {isStreaming && <div className="absolute inset-0 w-2 h-2 bg-success rounded-full animate-ping opacity-75" />}
                    </div>
                    <span className={cn("text-[10px] font-bold uppercase", isStreaming ? "text-success" : "text-muted-foreground")}>
                      {isStreaming ? 'Live' : 'Static'}
                    </span>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
                  <div className="flex bg-muted p-0.5 rounded-md text-[10px]">
                    <button 
                      onClick={() => setLevelFilter('all')}
                      className={cn("px-2 py-1 rounded-[4px] transition-all", levelFilter === 'all' ? "bg-background shadow-sm font-bold" : "text-muted-foreground")}
                    >All</button>
                    <button 
                      onClick={() => setLevelFilter('error')}
                      className={cn("px-2 py-1 rounded-[4px] transition-all", levelFilter === 'error' ? "bg-destructive text-destructive-foreground shadow-sm font-bold" : "text-muted-foreground")}
                    >Errors</button>
                    <button 
                      onClick={() => setLevelFilter('success')}
                      className={cn("px-2 py-1 rounded-[4px] transition-all", levelFilter === 'success' ? "bg-success text-success-foreground shadow-sm font-bold" : "text-muted-foreground")}
                    >Success</button>
                  </div>
                  <Button variant={isStreaming ? "default" : "outline"} size="sm" className="h-8 text-xs" onClick={handleToggleStream} disabled={!logProcessingEnabled && !isStreaming}>
                    {isStreaming ? 'Stop' : 'Stream'}
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm border-collapse">
                    <thead className="bg-muted/30 text-[10px] uppercase font-bold text-muted-foreground sticky top-0 backdrop-blur z-10 border-b">
                      <tr>
                        <th className="px-4 py-3 text-left w-24 cursor-pointer hover:text-foreground transition-colors" onClick={() => toggleSort('t')}>
                          <div className="flex items-center gap-1">Time {sortConfig.key === 't' && (sortConfig.direction === 'asc' ? '↑' : '↓')}</div>
                        </th>
                        <th className="px-4 py-3 text-left w-32 cursor-pointer hover:text-foreground transition-colors" onClick={() => toggleSort('ip')}>
                          <div className="flex items-center gap-1">Client IP {sortConfig.key === 'ip' && (sortConfig.direction === 'asc' ? '↑' : '↓')}</div>
                        </th>
                        <th className="px-4 py-3 text-left w-20 cursor-pointer hover:text-foreground transition-colors" onClick={() => toggleSort('method')}>
                          <div className="flex items-center gap-1">Method {sortConfig.key === 'method' && (sortConfig.direction === 'asc' ? '↑' : '↓')}</div>
                        </th>
                        <th className="px-4 py-3 text-left cursor-pointer hover:text-foreground transition-colors" onClick={() => toggleSort('path')}>
                          <div className="flex items-center gap-1">Path {sortConfig.key === 'path' && (sortConfig.direction === 'asc' ? '↑' : '↓')}</div>
                        </th>
                        <th className="px-4 py-3 text-left w-20 cursor-pointer hover:text-foreground transition-colors" onClick={() => toggleSort('status')}>
                          <div className="flex items-center gap-1">Status {sortConfig.key === 'status' && (sortConfig.direction === 'asc' ? '↑' : '↓')}</div>
                        </th>
                        <th className="px-4 py-3 text-left w-24 cursor-pointer hover:text-foreground transition-colors" onClick={() => toggleSort('duration')}>
                          <div className="flex items-center gap-1">Duration {sortConfig.key === 'duration' && (sortConfig.direction === 'asc' ? '↑' : '↓')}</div>
                        </th>
                        <th className="px-4 py-3 text-left w-32 cursor-pointer hover:text-foreground transition-colors" onClick={() => toggleSort('service')}>
                          <div className="flex items-center gap-1">Service {sortConfig.key === 'service' && (sortConfig.direction === 'asc' ? '↑' : '↓')}</div>
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y">
                      {filteredLogs.length > 0 ? (
                        filteredLogs.map((log, i) => (
                          <tr 
                            key={i} 
                            onClick={() => setSelectedLog(log)}
                            className="group hover:bg-muted/50 transition-colors cursor-pointer active:bg-muted"
                          >
                            <td className="px-4 py-2.5 text-[11px] text-muted-foreground font-mono tabular-nums">
                              {log.t ? new Date(log.t).toLocaleTimeString() : '—'}
                            </td>
                            <td className="px-4 py-2.5 text-xs font-mono text-muted-foreground group-hover:text-foreground">
                              {log.ip || '—'}
                            </td>
                            <td className="px-4 py-2.5">
                              <Badge variant="outline" className={cn("px-1.5 py-0 text-[9px] font-bold border", getMethodStyles(log.method))}>
                                {log.method || '—'}
                              </Badge>
                            </td>
                            <td className="px-4 py-2.5 text-xs font-mono truncate max-w-[300px]" title={log.path}>
                              {log.path || '—'}
                            </td>
                            <td className="px-4 py-2.5">
                              <Badge variant={getStatusVariant(log.status)} className="px-1.5 py-0 text-[9px] font-bold min-w-[32px] justify-center">
                                {log.status || '—'}
                              </Badge>
                            </td>
                            <td className="px-4 py-2.5 text-[11px] text-muted-foreground tabular-nums">
                              {formatDuration(log.Duration ?? log.duration)}
                            </td>
                            <td className="px-4 py-2.5 text-[11px] text-muted-foreground truncate max-w-[120px]" title={log.service}>
                              {log.service || '—'}
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={7} className="py-20 text-center">
                            <div className="flex flex-col items-center justify-center gap-3 text-muted-foreground">
                              <FileText className="h-10 w-10 opacity-10" />
                              <p className="text-sm font-medium">{isStreaming ? 'Waiting for incoming logs...' : 'No logs found matching your filters'}</p>
                              <Button variant="link" size="sm" onClick={() => { setLevelFilter('all'); toast.info('Filters reset') }}>Reset filters</Button>
                            </div>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
                {filteredLogs.length > 0 && (
                  <div className="px-4 py-3 bg-muted/10 border-t text-[10px] text-muted-foreground flex justify-between items-center">
                    <span>Showing {filteredLogs.length} of {parsedLogs.length} entries</span>
                    <span className="italic">Click any row to view full details</span>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <TraefikLogDetail 
            log={selectedLog} 
            open={!!selectedLog} 
            onOpenChange={(open) => !open && setSelectedLog(null)} 
          />
        </TabsContent>

      </Tabs>
    </div>
  )
}