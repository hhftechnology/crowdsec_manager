import { useState, useMemo, useCallback, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { CrowdSecAlert } from '@/lib/api'
import { crowdsecAPI } from '@/lib/api/crowdsec'
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
  RefreshCw,
  AlertCircle,
  Download,
  Search,
  LayoutGrid,
  TableProperties,
  Eye,
  Loader2,
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
  includeAll?: boolean
}

const FILTER_KEYS = [
  'id', 'since', 'until', 'ip', 'range',
  'scope', 'value', 'scenario', 'type', 'origin', 'includeAll',
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
]

const ALERT_INFO_ITEMS = [
  { label: 'Time Filters', text: 'Use duration format like 4h (4 hours), 30d (30 days), 1w (1 week)' },
  { label: 'IP/Range', text: 'Filter alerts from specific source IPs or IP ranges (CIDR notation)' },
  { label: 'Scope', text: 'Filter by scope (ip, range)' },
  { label: 'Scenario', text: 'Filter by specific scenario (e.g., crowdsecurity/ssh-bf)' },
  { label: 'Type', text: 'Filter alerts by their associated decision type (ban, captcha, throttle)' },
  { label: 'Origin', text: 'Filter by alert source (cscli, crowdsec, console, lists, CAPI)' },
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

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function AlertInspectDialog({
  alertId,
  open,
  onOpenChange,
}: {
  alertId: number
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { data, isLoading } = useQuery({
    queryKey: ['alert-inspect', alertId],
    queryFn: async () => {
      const response = await crowdsecAPI.inspectAlert(alertId)
      return response.data.data
    },
    enabled: open,
  })

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Alert #{alertId} Details</DialogTitle>
          <DialogDescription>Full inspection data from CrowdSec LAPI</DialogDescription>
        </DialogHeader>
        {isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground gap-2">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading...
          </div>
        ) : data ? (
          <pre className="p-4 bg-muted rounded-lg text-xs overflow-x-auto whitespace-pre-wrap font-mono">
            {JSON.stringify(data, null, 2)}
          </pre>
        ) : (
          <p className="text-muted-foreground text-sm">No data available</p>
        )}
      </DialogContent>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Main page component
// ---------------------------------------------------------------------------

export default function AlertAnalysis() {
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
  const [inspectAlertId, setInspectAlertId] = useState<number | null>(null)
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

  // ---- Client-side search filtering ----

  const filteredAlerts = useMemo(() => {
    if (!alertsData?.alerts) return []
    if (!searchQuery.trim()) return alertsData.alerts as CrowdSecAlert[]

    const q = searchQuery.toLowerCase()
    return (alertsData.alerts as CrowdSecAlert[]).filter((alert) => {
      const searchable = [
        String(alert.id),
        alert.scenario,
        alert.scope,
        alert.value,
        alert.origin,
        alert.type,
        alert.message,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
      return searchable.includes(q)
    })
  }, [alertsData, searchQuery])

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

  const handleExport = useCallback(() => {
    if (!alertsData?.alerts || alertsData.alerts.length === 0) {
      toast.error('No data to export')
      return
    }

    const headers = ['ID', 'Scenario', 'Scope', 'Value', 'Origin', 'Type', 'Events Count', 'Start At', 'Stop At']
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
                  : `${totalCount} alerts found`}
              </CardDescription>
            </div>
            <div className="flex gap-2 flex-wrap">
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
              placeholder="Search by IP, scenario, origin, or any text..."
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
                        <TableHead>Origin</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead className="w-20 text-right">Events</TableHead>
                        <TableHead>Time</TableHead>
                        <TableHead className="w-16">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {items.map((alert, index) => (
                        <TableRow key={alert.id ?? index}>
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
                            {alert.id != null && (
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-8 w-8"
                                onClick={() => setInspectAlertId(alert.id)}
                              >
                                <Eye className="h-4 w-4" />
                              </Button>
                            )}
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

      {inspectAlertId !== null && (
        <AlertInspectDialog
          alertId={inspectAlertId}
          open={true}
          onOpenChange={(open) => {
            if (!open) setInspectAlertId(null)
          }}
        />
      )}
    </div>
  )
}
