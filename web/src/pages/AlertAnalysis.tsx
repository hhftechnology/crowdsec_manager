import { useState, useMemo, useCallback, useEffect } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { CrowdSecAlert } from '@/lib/api'
import { crowdsecAPI } from '@/lib/api/crowdsec'
import type { Decision, AlertEvent } from '@/lib/api/types'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  RefreshCw,
  AlertCircle,
  Download,
  Search,
  LayoutGrid,
  TableProperties,
  Eye,
  Loader2,
  Trash2,
  MapPin,
  Globe,
  Shield,
  Info,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from 'lucide-react'
import {
  PageHeader,
  EmptyState,
  PageLoader,
  InfoCard,
  ResultsSummary,
  CrowdSecFilterForm,
  SCOPE_OPTIONS,
  TYPE_OPTIONS,
  ORIGIN_OPTIONS,
  QueryError,
  ScenarioName,
  TimeDisplay,
  CountryFlag,
} from '@/components/common'
import type { FilterField } from '@/components/common'
import { AlertCard } from '@/components/alerts/AlertCard'
import { ChartCard, AreaTimeline, BarDistribution } from '@/components/charts'
import { groupByField } from '@/lib/chart-utils'
import { useInfiniteScroll, useUrlFilters } from '@/hooks'
import { useSearch } from '@/contexts/SearchContext'

// ---------------------------------------------------------------------------
// Types & constants
// ---------------------------------------------------------------------------

interface AlertFilters {
  [key: string]: string | boolean | undefined
  id?: string
  since?: string
  until?: string
  ip?: string
  range?: string
  scope?: string
  value?: string
  scenario?: string
  type?: string
  origin?: string
  country?: string
  includeAll?: boolean
}

const FILTER_KEYS = [
  'id', 'since', 'until', 'ip', 'range',
  'scope', 'value', 'scenario', 'type', 'origin', 'country', 'includeAll',
]

const FILTER_DEFAULTS: AlertFilters = {}

const ALERT_FILTER_FIELDS: FilterField[] = [
  { id: 'id', label: 'Alert ID', type: 'input', placeholder: '123' },
  { id: 'since', label: 'Since (e.g., 4h, 30d)', type: 'input', placeholder: '4h' },
  { id: 'until', label: 'Until (e.g., 1h, 7d)', type: 'input', placeholder: '1h' },
  { id: 'ip', label: 'Source IP Address', type: 'input', placeholder: '192.168.1.100' },
  { id: 'range', label: 'IP Range (CIDR)', type: 'input', placeholder: '192.168.1.0/24' },
  { id: 'scope', label: 'Scope', type: 'select', options: SCOPE_OPTIONS },
  { id: 'value', label: 'Value', type: 'input', placeholder: 'Match specific value' },
  { id: 'scenario', label: 'Scenario', type: 'input', placeholder: 'crowdsecurity/ssh-bf' },
  { id: 'type', label: 'Decision Type', type: 'select', options: TYPE_OPTIONS },
  { id: 'origin', label: 'Origin', type: 'select', options: ORIGIN_OPTIONS },
  { id: 'country', label: 'Country (ISO code)', type: 'input', placeholder: 'US, FR, DE...' },
]

const ALERT_INFO_ITEMS = [
  { label: 'Time Filters', text: 'Use duration format like 4h (4 hours), 30d (30 days), 1w (1 week)' },
  { label: 'IP/Range', text: 'Filter alerts from specific source IPs or IP ranges (CIDR notation)' },
  { label: 'Scope', text: 'Filter by scope (ip, range)' },
  { label: 'Scenario', text: 'Filter by specific scenario (e.g., crowdsecurity/ssh-bf)' },
  { label: 'Type', text: 'Filter alerts by their associated decision type (ban, captcha, throttle)' },
  { label: 'Origin', text: 'Filter by alert source (cscli, crowdsec, console, lists, CAPI)' },
  { label: 'Country', text: 'Filter by ISO country code (e.g., US, FR, DE). Click a country flag to filter.' },
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Escape a value for safe CSV output (RFC 4180). */
function escapeCsvField(field: string | number | undefined | null): string {
  const str = String(field ?? '')
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    return `"${str.replace(/"/g, '""')}"`
  }
  return str
}

/** Truncate a string and add ellipsis if exceeding max length. */
function truncate(str: string | undefined | null, max: number): string {
  if (!str) return '-'
  return str.length > max ? str.slice(0, max) + '...' : str
}

/** Format an event's meta array into a readable key-value display. */
function formatEventMeta(meta: Record<string, string>[] | undefined): { key: string; value: string }[] {
  if (!meta || !Array.isArray(meta)) return []
  return meta.map((m) => {
    const key = m.key || Object.keys(m).find((k) => k !== 'value') || 'unknown'
    const value = m.value || m[key] || ''
    return { key, value }
  })
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/** Rich alert detail modal inspired by crowdsec-web-ui. */
function AlertDetailModal({
  alert,
  open,
  onOpenChange,
}: {
  alert: CrowdSecAlert
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [showAllEvents, setShowAllEvents] = useState(false)

  const { data: inspectData, isLoading } = useQuery({
    queryKey: ['alert-inspect', alert.id],
    queryFn: async () => {
      const response = await crowdsecAPI.inspectAlert(alert.id)
      return response.data.data
    },
    enabled: open && alert.id != null,
  })

  // Merge inspect data with the list alert data for completeness
  const fullAlert = inspectData ?? alert
  const decisions = fullAlert.decisions ?? []
  const events: AlertEvent[] = fullAlert.events ?? []
  const visibleEvents = showAllEvents ? events : events.slice(0, 5)

  const source = fullAlert.source ?? alert.source
  const hasCoords = source?.latitude != null && source?.longitude != null
  const mapsUrl = hasCoords
    ? `https://www.google.com/maps?q=${source!.latitude},${source!.longitude}`
    : null

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-destructive" />
            Alert #{alert.id} - <ScenarioName scenario={fullAlert.scenario} />
          </DialogTitle>
          <DialogDescription>
            Detailed alert inspection from CrowdSec LAPI
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground gap-2">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading alert details...
          </div>
        ) : (
          <div className="space-y-5">
            {/* Info cards grid */}
            <div className="grid gap-3 grid-cols-1 sm:grid-cols-3">
              {/* Scenario card */}
              <Card>
                <CardContent className="pt-4 pb-3 px-4 space-y-1">
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground font-medium uppercase tracking-wide">
                    <AlertCircle className="h-3.5 w-3.5" />
                    Scenario
                  </div>
                  <div className="text-sm font-medium">
                    <ScenarioName scenario={fullAlert.scenario} />
                  </div>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Badge variant="secondary" className="text-xs">{fullAlert.origin}</Badge>
                    {fullAlert.type && (
                      <Badge variant={fullAlert.type === 'ban' ? 'destructive' : 'default'} className="text-xs">
                        {fullAlert.type}
                      </Badge>
                    )}
                  </div>
                  {fullAlert.events_count != null && (
                    <p className="text-xs text-muted-foreground">
                      {fullAlert.events_count} event{fullAlert.events_count !== 1 ? 's' : ''}
                    </p>
                  )}
                </CardContent>
              </Card>

              {/* Location card */}
              <Card>
                <CardContent className="pt-4 pb-3 px-4 space-y-1">
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground font-medium uppercase tracking-wide">
                    <MapPin className="h-3.5 w-3.5" />
                    Location
                  </div>
                  <div className="text-sm">
                    <CountryFlag code={source?.cn} showName />
                  </div>
                  {hasCoords && (
                    <a
                      href={mapsUrl!}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs text-blue-500 hover:text-blue-600 hover:underline"
                    >
                      {source!.latitude!.toFixed(4)}, {source!.longitude!.toFixed(4)}
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                  {!hasCoords && (
                    <p className="text-xs text-muted-foreground">No coordinates available</p>
                  )}
                </CardContent>
              </Card>

              {/* IP info card */}
              <Card>
                <CardContent className="pt-4 pb-3 px-4 space-y-1">
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground font-medium uppercase tracking-wide">
                    <Globe className="h-3.5 w-3.5" />
                    IP Info
                  </div>
                  <p className="text-sm font-mono font-medium">{fullAlert.value || source?.ip || '-'}</p>
                  {source?.as_name && (
                    <p className="text-xs text-muted-foreground" title={source.as_name}>
                      {source.as_number ? `AS${source.as_number} - ` : ''}
                      {truncate(source.as_name, 40)}
                    </p>
                  )}
                  {source?.range && (
                    <p className="text-xs text-muted-foreground font-mono">{source.range}</p>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Message box */}
            {fullAlert.message && (
              <div className="flex items-start gap-2.5 p-3 rounded-lg bg-blue-500/10 border border-blue-500/20 text-sm">
                <Info className="h-4 w-4 text-blue-500 shrink-0 mt-0.5" />
                <span className="text-foreground">{fullAlert.message}</span>
              </div>
            )}

            {/* Decisions table */}
            {decisions.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-sm font-semibold">Decisions Taken ({decisions.length})</h4>
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-16">ID</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Value</TableHead>
                        <TableHead>Duration</TableHead>
                        <TableHead>Origin</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {decisions.map((d: Decision, idx: number) => (
                        <TableRow key={d.id ?? idx}>
                          <TableCell className="font-mono text-xs">{d.id}</TableCell>
                          <TableCell>
                            <Badge variant={d.type === 'ban' ? 'destructive' : 'default'} className="text-xs">
                              {d.type}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs">{d.value}</TableCell>
                          <TableCell className="text-xs">{d.duration}</TableCell>
                          <TableCell>
                            <Badge variant="secondary" className="text-xs">{d.origin}</Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            )}
            {decisions.length === 0 && (
              <p className="text-sm text-muted-foreground">No decisions associated with this alert.</p>
            )}

            {/* Events */}
            <div className="space-y-2">
              <h4 className="text-sm font-semibold">Events ({events.length})</h4>
              {events.length === 0 ? (
                <p className="text-sm text-muted-foreground">No event data available.</p>
              ) : (
                <div className="space-y-2">
                  {visibleEvents.map((event, idx) => (
                    <div key={idx} className="rounded-md border p-3 text-xs space-y-1">
                      <div className="flex items-center gap-2 text-muted-foreground">
                        <span className="font-mono font-medium text-foreground">
                          Event #{idx + 1}
                        </span>
                        {event.timestamp && (
                          <span className="font-mono">
                            <TimeDisplay date={event.timestamp} />
                          </span>
                        )}
                      </div>
                      {event.meta && (
                        <div className="grid gap-1 mt-1">
                          {formatEventMeta(event.meta).map((m, mIdx) => (
                            <div key={mIdx} className="flex gap-2">
                              <span className="font-mono text-muted-foreground shrink-0 min-w-[100px]">
                                {m.key}:
                              </span>
                              <span className="font-mono break-all">{m.value}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                  {events.length > 5 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="w-full text-xs"
                      onClick={() => setShowAllEvents((prev) => !prev)}
                    >
                      {showAllEvents ? (
                        <>
                          <ChevronUp className="h-3.5 w-3.5 mr-1" />
                          Show fewer events
                        </>
                      ) : (
                        <>
                          <ChevronDown className="h-3.5 w-3.5 mr-1" />
                          Show all {events.length} events
                        </>
                      )}
                    </Button>
                  )}
                </div>
              )}
            </div>

            {/* Timestamps */}
            <div className="flex gap-4 text-xs text-muted-foreground border-t pt-3">
              <span>
                Started: <TimeDisplay date={fullAlert.start_at} />
              </span>
              {fullAlert.stop_at && (
                <span>
                  Stopped: <TimeDisplay date={fullAlert.stop_at} />
                </span>
              )}
              {fullAlert.simulated && (
                <Badge variant="outline" className="text-xs">Simulated</Badge>
              )}
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

/** Confirmation dialog for alert deletion. */
function DeleteAlertDialog({
  alertId,
  open,
  onOpenChange,
  onConfirm,
  isDeleting,
}: {
  alertId: number
  open: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: () => void
  isDeleting: boolean
}) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete Alert #{alertId}?</AlertDialogTitle>
          <AlertDialogDescription>
            This will also delete all associated decisions. This action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={isDeleting}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={onConfirm}
            disabled={isDeleting}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            {isDeleting ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Deleting...
              </>
            ) : (
              <>
                <Trash2 className="h-4 w-4 mr-2" />
                Delete
              </>
            )}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

// ---------------------------------------------------------------------------
// Main page component
// ---------------------------------------------------------------------------

export default function AlertAnalysis() {
  const queryClient = useQueryClient()

  // URL-synced filter state (editable form values)
  const [filters, setFilter, resetFilters] = useUrlFilters<AlertFilters>(FILTER_KEYS, FILTER_DEFAULTS)

  // Active filters are what the query actually uses (applied on submit)
  const [activeFilters, setActiveFilters] = useState<AlertFilters>(() => {
    const initial: AlertFilters = {}
    for (const key of FILTER_KEYS) {
      if (filters[key] !== undefined && filters[key] !== '' && filters[key] !== false) {
        initial[key] = filters[key]
      }
    }
    return initial
  })

  const [expandedAlert, setExpandedAlert] = useState<number | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [viewMode, setViewMode] = useState<'cards' | 'table'>('cards')
  const [detailAlert, setDetailAlert] = useState<CrowdSecAlert | null>(null)
  const [deleteAlertId, setDeleteAlertId] = useState<number | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)
  const { query, setQuery } = useSearch()

  // ---- Data fetching ----

  const { data: alertsData, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['alerts-analysis', activeFilters],
    queryFn: async () => {
      const response = await api.crowdsec.getAlertsAnalysis(activeFilters)
      return response.data.data
    },
    refetchInterval: 30000,
  })

  useEffect(() => {
    if (query !== searchQuery) {
      setSearchQuery(query)
    }
  }, [query, searchQuery])

  // ---- Client-side search filtering (includes country + AS) ----

  const filteredAlerts = useMemo(() => {
    if (!alertsData?.alerts) return []
    let alerts = alertsData.alerts as CrowdSecAlert[]

    // Country filter from URL params (client-side since the API may not support it)
    const countryFilter = activeFilters.country?.toUpperCase()
    if (countryFilter) {
      alerts = alerts.filter((a) => a.source?.cn?.toUpperCase() === countryFilter)
    }

    if (!searchQuery.trim()) return alerts

    const q = searchQuery.toLowerCase()
    return alerts.filter((alert) => {
      const searchable = [
        String(alert.id),
        alert.scenario,
        alert.scope,
        alert.value,
        alert.origin,
        alert.type,
        alert.message,
        alert.source?.cn,
        alert.source?.as_name,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
      return searchable.includes(q)
    })
  }, [alertsData, searchQuery, activeFilters.country])

  // ---- Infinite scroll ----

  const { items, hasMore, sentinelRef } = useInfiniteScroll<CrowdSecAlert>({
    data: filteredAlerts,
    pageSize: 50,
  })

  // ---- Chart data ----

  const alertTimeData = useMemo(() => {
    if (!alertsData?.alerts) return []
    const buckets: Record<string, number> = {}
    for (const a of alertsData.alerts as CrowdSecAlert[]) {
      const date = new Date(a.start_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
      buckets[date] = (buckets[date] || 0) + 1
    }
    return Object.entries(buckets).map(([date, count]) => ({ date, value: count }))
  }, [alertsData])

  const scenarioData = useMemo(() => {
    if (!alertsData?.alerts) return []
    return groupByField(alertsData.alerts, 'scenario', 8)
  }, [alertsData])

  // ---- Handlers ----

  const handleApplyFilters = useCallback(() => {
    setActiveFilters({ ...filters })
    toast.success('Filters applied')
  }, [filters])

  const handleResetFilters = useCallback(() => {
    resetFilters()
    setActiveFilters({})
    setSearchQuery('')
    toast.info('Filters reset')
  }, [resetFilters])

  const handleFilterChange = useCallback(
    (key: string, value: string | boolean) => {
      setFilter(key, value)
    },
    [setFilter],
  )

  const handleCountryClick = useCallback(
    (countryCode: string | undefined | null) => {
      if (!countryCode) return
      const code = countryCode.toUpperCase()
      setFilter('country', code)
      setActiveFilters((prev) => ({ ...prev, country: code }))
      toast.success(`Filtering by country: ${code}`)
    },
    [setFilter],
  )

  const handleDeleteAlert = useCallback(async () => {
    if (deleteAlertId == null) return
    setIsDeleting(true)
    try {
      await crowdsecAPI.deleteAlert(deleteAlertId)
      toast.success(`Alert #${deleteAlertId} deleted`)
      setDeleteAlertId(null)
      // Close the detail modal if this alert was being inspected
      if (detailAlert?.id === deleteAlertId) {
        setDetailAlert(null)
      }
      // Invalidate and refetch
      queryClient.invalidateQueries({ queryKey: ['alerts-analysis'] })
      queryClient.invalidateQueries({ queryKey: ['alert-inspect', deleteAlertId] })
    } catch (err) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error || 'Failed to delete alert'
      toast.error(msg)
    } finally {
      setIsDeleting(false)
    }
  }, [deleteAlertId, detailAlert, queryClient])

  const handleExport = useCallback(() => {
    if (!alertsData?.alerts || alertsData.alerts.length === 0) {
      toast.error('No data to export')
      return
    }

    const headers = ['ID', 'Scenario', 'Scope', 'Value', 'Origin', 'Type', 'Country', 'AS Name', 'Events Count', 'Start At', 'Stop At']
    const csvContent = [
      headers.map(escapeCsvField).join(','),
      ...(alertsData.alerts as CrowdSecAlert[]).map((a) =>
        [
          escapeCsvField(a.id),
          escapeCsvField(a.scenario),
          escapeCsvField(a.scope),
          escapeCsvField(a.value),
          escapeCsvField(a.origin),
          escapeCsvField(a.type || 'N/A'),
          escapeCsvField(a.source?.cn || ''),
          escapeCsvField(a.source?.as_name || ''),
          escapeCsvField(a.events_count || 0),
          escapeCsvField(a.start_at),
          escapeCsvField(a.stop_at || 'Ongoing'),
        ].join(','),
      ),
    ].join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `crowdsec-alerts-${new Date().toISOString()}.csv`
    anchor.click()
    window.URL.revokeObjectURL(url)
    toast.success('Alerts exported successfully')
  }, [alertsData])

  // ---- Derived values ----

  const totalCount = alertsData?.count || 0
  const displayedCount = filteredAlerts.length

  // ---- Render ----

  return (
    <div className="space-y-6">
      <PageHeader
        title="Alert List Analysis"
        description="Advanced filtering and analysis of CrowdSec alerts"
        breadcrumbs="Activity / Alerts"
        actions={
          totalCount > 0 ? (
            <Badge variant="secondary" className="text-sm px-3 py-1">
              {totalCount} alert{totalCount !== 1 ? 's' : ''}
            </Badge>
          ) : undefined
        }
      />

      {isError && <QueryError error={error} onRetry={refetch} />}

      {alertsData?.alerts && (alertsData.alerts as CrowdSecAlert[]).length > 0 && (
        <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
          <ChartCard title="Alerts Over Time" description="Alert frequency by date">
            <AreaTimeline
              data={alertTimeData}
              height={250}
              color="hsl(var(--chart-1))"
            />
          </ChartCard>
          <ChartCard title="Top Scenarios" description="Most triggered scenarios">
            <BarDistribution
              data={scenarioData}
              height={250}
              layout="horizontal"
            />
          </ChartCard>
        </div>
      )}

      <CrowdSecFilterForm
        fields={ALERT_FILTER_FIELDS}
        filters={filters}
        onFilterChange={handleFilterChange}
        onApply={handleApplyFilters}
        onReset={handleResetFilters}
        description="Apply filters to analyze specific alerts based on CrowdSec criteria"
        showIncludeAll
        includeAllLabel="Include alerts from Central API"
      />

      <Card>
        <CardHeader>
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle>Alert Results</CardTitle>
              <CardDescription>
                {searchQuery
                  ? `${displayedCount} of ${totalCount} alerts matching "${searchQuery}"`
                  : activeFilters.country
                    ? `${displayedCount} of ${totalCount} alerts from ${activeFilters.country}`
                    : `${totalCount} alerts found`}
              </CardDescription>
            </div>
            <div className="flex gap-2 flex-wrap">
              {activeFilters.country && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setFilter('country', '')
                    setActiveFilters((prev) => {
                      const next = { ...prev }
                      delete next.country
                      return next
                    })
                    toast.info('Country filter cleared')
                  }}
                >
                  <CountryFlag code={activeFilters.country} showName={false} />
                  <span className="ml-1">{activeFilters.country}</span>
                  <span className="ml-1 text-muted-foreground">x</span>
                </Button>
              )}
              <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isLoading}>
                <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
              <Button variant="outline" size="sm" onClick={handleExport}>
                <Download className="h-4 w-4 mr-2" />
                Export CSV
              </Button>
            </div>
          </div>

          <div className="relative mt-2">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by IP, scenario, origin, country, AS name..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value)
                setQuery(e.target.value)
              }}
              className="pl-9"
            />
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          <ResultsSummary
            total={totalCount}
            filtered={displayedCount}
            label="alerts"
            query={searchQuery || undefined}
          />
          {isLoading ? (
            <PageLoader message="Loading alerts..." />
          ) : filteredAlerts.length > 0 ? (
            <Tabs
              value={viewMode}
              onValueChange={(v) => setViewMode(v as 'cards' | 'table')}
            >
              <TabsList className="mb-4">
                <TabsTrigger value="cards" className="gap-1.5">
                  <LayoutGrid className="h-4 w-4" />
                  Cards
                </TabsTrigger>
                <TabsTrigger value="table" className="gap-1.5">
                  <TableProperties className="h-4 w-4" />
                  Table
                </TabsTrigger>
              </TabsList>

              {/* ---- Card view ---- */}
              <TabsContent value="cards">
                <div className="space-y-2">
                  {items.map((alert, index) => (
                    <AlertCard
                      key={alert.id ?? index}
                      alert={alert}
                      index={index}
                      isExpanded={expandedAlert === (alert.id ?? index)}
                      onToggle={() =>
                        setExpandedAlert(
                          expandedAlert === (alert.id ?? index) ? null : (alert.id ?? index),
                        )
                      }
                    />
                  ))}
                </div>
                <div ref={sentinelRef as React.Ref<HTMLDivElement>} className="h-4" />
                {hasMore && (
                  <div className="flex items-center justify-center py-4 text-sm text-muted-foreground gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading more...
                  </div>
                )}
              </TabsContent>

              {/* ---- Table view ---- */}
              <TabsContent value="table">
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-16">ID</TableHead>
                        <TableHead>Scenario</TableHead>
                        <TableHead>Source IP</TableHead>
                        <TableHead className="w-28">Country</TableHead>
                        <TableHead>AS</TableHead>
                        <TableHead>Origin</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead className="w-20 text-right">Events</TableHead>
                        <TableHead>Time</TableHead>
                        <TableHead className="w-24">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {items.map((alert, index) => (
                        <TableRow
                          key={alert.id ?? index}
                          className="cursor-pointer hover:bg-muted/50"
                          onClick={() => {
                            if (alert.id != null) setDetailAlert(alert)
                          }}
                        >
                          <TableCell className="font-mono text-xs">
                            {alert.id}
                          </TableCell>
                          <TableCell>
                            <ScenarioName scenario={alert.scenario} />
                          </TableCell>
                          <TableCell className="font-mono text-sm">
                            {alert.value}
                          </TableCell>
                          <TableCell>
                            <button
                              type="button"
                              className="hover:opacity-80 transition-opacity"
                              onClick={(e) => {
                                e.stopPropagation()
                                handleCountryClick(alert.source?.cn)
                              }}
                              title={alert.source?.cn ? `Filter by ${alert.source.cn}` : undefined}
                            >
                              <CountryFlag code={alert.source?.cn} showName={false} />
                            </button>
                          </TableCell>
                          <TableCell className="text-xs max-w-[160px] truncate" title={alert.source?.as_name || ''}>
                            {truncate(alert.source?.as_name, 24)}
                          </TableCell>
                          <TableCell>
                            <Badge variant="secondary">{alert.origin}</Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant={alert.type === 'ban' ? 'destructive' : 'default'}>
                              {alert.type || 'unknown'}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-right tabular-nums">
                            {alert.events_count ?? 0}
                          </TableCell>
                          <TableCell>
                            <TimeDisplay date={alert.start_at} />
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                              {alert.id != null && (
                                <>
                                  <Button
                                    variant="ghost"
                                    size="icon"
                                    className="h-8 w-8"
                                    onClick={() => setDetailAlert(alert)}
                                    title="View details"
                                  >
                                    <Eye className="h-4 w-4" />
                                  </Button>
                                  <Button
                                    variant="ghost"
                                    size="icon"
                                    className="h-8 w-8 text-destructive hover:text-destructive"
                                    onClick={() => setDeleteAlertId(alert.id)}
                                    title="Delete alert"
                                  >
                                    <Trash2 className="h-4 w-4" />
                                  </Button>
                                </>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
                <div ref={sentinelRef as React.Ref<HTMLDivElement>} className="h-4" />
                {hasMore && (
                  <div className="flex items-center justify-center py-4 text-sm text-muted-foreground gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading more...
                  </div>
                )}
              </TabsContent>
            </Tabs>
          ) : (
            <EmptyState
              icon={AlertCircle}
              title="No alerts found"
              description={
                searchQuery
                  ? `No alerts match "${searchQuery}". Try a different search term.`
                  : 'Try adjusting your filters or check back later'
              }
            />
          )}
        </CardContent>
      </Card>

      <InfoCard
        title="Filter Information"
        description="Understanding alert list filters"
        items={ALERT_INFO_ITEMS}
      />

      {/* Rich alert detail modal */}
      {detailAlert !== null && (
        <AlertDetailModal
          alert={detailAlert}
          open={true}
          onOpenChange={(open) => {
            if (!open) setDetailAlert(null)
          }}
        />
      )}

      {/* Delete confirmation dialog */}
      {deleteAlertId !== null && (
        <DeleteAlertDialog
          alertId={deleteAlertId}
          open={true}
          onOpenChange={(open) => {
            if (!open) setDeleteAlertId(null)
          }}
          onConfirm={handleDeleteAlert}
          isDeleting={isDeleting}
        />
      )}
    </div>
  )
}
