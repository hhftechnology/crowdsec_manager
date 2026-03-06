import { useState, useMemo, useCallback, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams, Link } from 'react-router-dom'
import { toast } from 'sonner'
import api, { Decision } from '@/lib/api'
import type { RepeatedOffender } from '@/lib/api'
import type { AlertSource } from '@/lib/api/types'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { Switch } from '@/components/ui/switch'
import { RefreshCw, AlertCircle, Download, Trash2, Search, Shield } from 'lucide-react'
import { AddDecisionDialog } from '@/components/decisions/AddDecisionDialog'
import { ImportDecisionsDialog } from '@/components/decisions/ImportDecisionsDialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  PageHeader, EmptyState, PageLoader, InfoCard, CrowdSecFilterForm, ResultsSummary,
  SCOPE_OPTIONS, TYPE_OPTIONS, ORIGIN_OPTIONS, QueryError,
  ScenarioName, TimeDisplay, formatDuration, expiresIn, CountryFlag,
} from '@/components/common'
import type { FilterField } from '@/components/common'
import { ChartCard, AreaTimeline, PieBreakdown, BarDistribution } from '@/components/charts'
import { groupByField } from '@/lib/chart-utils'
import { useInfiniteScroll } from '@/hooks'
import { useSSE } from '@/hooks/useSSE'
import { useSearch } from '@/contexts/SearchContext'

interface DecisionFilters {
  [key: string]: string | boolean | undefined
  since?: string
  until?: string
  type?: string
  scope?: string
  origin?: string
  value?: string
  scenario?: string
  ip?: string
  range?: string
  includeAll?: boolean
}

/** Row type when duplicates are collapsed */
interface CollapsedDecision extends Decision {
  _count: number
  _ids: number[]
}

const FILTER_PARAM_KEYS = ['since', 'until', 'type', 'scope', 'origin', 'value', 'scenario', 'ip', 'range'] as const

const DECISION_SCOPE_OPTIONS = [
  ...SCOPE_OPTIONS,
  { value: 'session', label: 'Session' },
]

const DECISION_FILTER_FIELDS: FilterField[] = [
  { id: 'since', label: 'Since (e.g., 4h, 30d)', type: 'input', placeholder: '4h' },
  { id: 'until', label: 'Until (e.g., 1h, 7d)', type: 'input', placeholder: '1h' },
  { id: 'type', label: 'Decision Type', type: 'select', options: TYPE_OPTIONS },
  { id: 'scope', label: 'Scope', type: 'select', options: DECISION_SCOPE_OPTIONS },
  { id: 'origin', label: 'Origin', type: 'select', options: ORIGIN_OPTIONS },
  { id: 'value', label: 'Value (IP, username, etc.)', type: 'input', placeholder: '1.2.3.4' },
  { id: 'scenario', label: 'Scenario', type: 'input', placeholder: 'crowdsecurity/ssh-bf' },
  { id: 'ip', label: 'IP Address', type: 'input', placeholder: '192.168.1.100' },
  { id: 'range', label: 'IP Range (CIDR)', type: 'input', placeholder: '192.168.1.0/24' },
]

const DECISION_INFO_ITEMS = [
  { label: 'Time Filters', text: 'Use duration format like 4h (4 hours), 30d (30 days), 1w (1 week)' },
  { label: 'Type', text: 'Filter by decision type (ban, captcha, throttle)' },
  { label: 'Scope', text: 'Filter by scope (ip, range, session)' },
  { label: 'Origin', text: 'Filter by source (cscli, crowdsec, console, lists, CAPI)' },
  { label: 'Value', text: 'Specific value to match (IP address, username, etc.)' },
  { label: 'Scenario', text: 'Filter by specific scenario (e.g., crowdsecurity/ssh-bf)' },
]

function escapeCSVField(field: unknown): string {
  const str = String(field ?? '')
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    return `"${str.replace(/"/g, '""')}"`
  }
  return str
}

/** Check whether a decision's `until` timestamp is in the past */
function isExpired(until?: string): boolean {
  if (!until) return false
  return new Date(until).getTime() < Date.now()
}

function parseFiltersFromParams(searchParams: URLSearchParams): DecisionFilters {
  const filters: DecisionFilters = {}
  for (const key of FILTER_PARAM_KEYS) {
    const val = searchParams.get(key)
    if (val) filters[key] = val
  }
  if (searchParams.get('includeAll') === 'true') {
    filters.includeAll = true
  }
  return filters
}

function syncFiltersToParams(filters: DecisionFilters, setSearchParams: ReturnType<typeof useSearchParams>[1]) {
  const params = new URLSearchParams()
  for (const key of FILTER_PARAM_KEYS) {
    const val = filters[key]
    if (val && typeof val === 'string' && val.length > 0) {
      params.set(key, val)
    }
  }
  if (filters.includeAll) {
    params.set('includeAll', 'true')
  }
  setSearchParams(params, { replace: true })
}

export default function DecisionAnalysis() {
  const [searchParams, setSearchParams] = useSearchParams()
  // Initialise filters from URL on mount
  const [filters, setFilters] = useState<DecisionFilters>(() => parseFiltersFromParams(searchParams))
  const [activeFilters, setActiveFilters] = useState<DecisionFilters>(() => parseFiltersFromParams(searchParams))

  const [deleteId, setDeleteId] = useState<number | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [bulkDeleting, setBulkDeleting] = useState(false)
  const [showBulkDeleteConfirm, setShowBulkDeleteConfirm] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [hideDuplicates, setHideDuplicates] = useState(false)
  const [hideExpired, setHideExpired] = useState(true)
  const { query, setQuery } = useSearch()
  const { lastEvent } = useSSE('/api/events/sse')
  const seenRealtimeEventsRef = useRef<Set<string>>(new Set())

  const { data: decisionsData, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['decisions-analysis', activeFilters],
    queryFn: async () => {
      const response = await api.crowdsec.getDecisionsAnalysis(activeFilters)
      return response.data.data
    },
    refetchInterval: 30000,
  })

  // Fetch alerts to enrich decisions with geo/AS data
  const { data: alertsData } = useQuery({
    queryKey: ['alerts-geo-enrichment', activeFilters],
    queryFn: async () => {
      const response = await api.crowdsec.getAlertsAnalysis({
        since: activeFilters.since,
        until: activeFilters.until,
        scenario: activeFilters.scenario,
        origin: activeFilters.origin,
        scope: activeFilters.scope,
        value: activeFilters.value,
        ip: activeFilters.ip,
        range: activeFilters.range,
        includeAll: activeFilters.includeAll,
      })
      return response.data.data
    },
    refetchInterval: 60000,
  })

  const { data: repeatedOffendersData } = useQuery({
    queryKey: ['repeated-offenders'],
    queryFn: async () => {
      const response = await api.crowdsec.getRepeatedOffenders()
      return response.data.data
    },
    refetchInterval: 60000,
  })

  // Build a lookup map: alert_id -> AlertSource
  const alertSourceMap = useMemo(() => {
    const map = new Map<number, AlertSource>()
    if (!alertsData?.alerts) return map
    for (const alert of alertsData.alerts) {
      if (alert.source) {
        map.set(alert.id, alert.source)
      }
    }
    return map
  }, [alertsData])

  // Sync active filters to URL whenever they change
  useEffect(() => {
    syncFiltersToParams(activeFilters, setSearchParams)
  }, [activeFilters, setSearchParams])

  useEffect(() => {
    if (query !== searchQuery) {
      setSearchQuery(query)
    }
  }, [query, searchQuery])

  useEffect(() => {
    if (!lastEvent || lastEvent.type !== 'crowdsec.repeated_offender') {
      return
    }

    const eventId = lastEvent.id ?? JSON.stringify(lastEvent.payload ?? {})
    if (seenRealtimeEventsRef.current.has(eventId)) {
      return
    }
    seenRealtimeEventsRef.current.add(eventId)

    const payload = (lastEvent.payload ?? {}) as Partial<RepeatedOffender>
    const value = payload.value ?? 'unknown'
    const count = payload.hit_count ?? 0
    toast.warning(`Repeated offender detected: ${value} (${count} hits in 30d)`)
  }, [lastEvent])

  // --- Chart data ---

  const decisionTimeData = useMemo(() => {
    if (!decisionsData?.decisions) return []
    const buckets: Record<string, number> = {}
    for (const d of decisionsData.decisions) {
      const date = new Date(d.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
      buckets[date] = (buckets[date] || 0) + 1
    }
    return Object.entries(buckets).map(([date, count]) => ({ date, value: count }))
  }, [decisionsData])

  const decisionTypeData = useMemo(() => {
    if (!decisionsData?.decisions) return []
    return groupByField(decisionsData.decisions, 'type', 5)
  }, [decisionsData])

  const topIPsData = useMemo(() => {
    if (!decisionsData?.decisions) return []
    return groupByField(decisionsData.decisions, 'value', 8)
  }, [decisionsData])

  // --- Client-side filtering (search + expired) ---

  const searchFiltered = useMemo(() => {
    let decisions = decisionsData?.decisions ?? []

    // Filter out expired decisions when toggle is on
    if (hideExpired) {
      decisions = decisions.filter((d: Decision) => !isExpired(d.until))
    }

    if (!searchQuery.trim()) return decisions
    const q = searchQuery.toLowerCase()
    return decisions.filter((d: Decision) =>
      d.value?.toLowerCase().includes(q) ||
      d.scenario?.toLowerCase().includes(q) ||
      d.origin?.toLowerCase().includes(q)
    )
  }, [decisionsData, searchQuery, hideExpired])

  // --- Collapse duplicates ---

  const displayDecisions = useMemo<CollapsedDecision[]>(() => {
    if (!hideDuplicates) {
      return searchFiltered.map((d: Decision) => ({ ...d, _count: 1, _ids: [d.id] }))
    }
    const groups = new Map<string, CollapsedDecision>()
    for (const d of searchFiltered) {
      const key = d.value
      const existing = groups.get(key)
      if (existing) {
        existing._count += 1
        existing._ids.push(d.id)
      } else {
        groups.set(key, { ...d, _count: 1, _ids: [d.id] })
      }
    }
    return Array.from(groups.values())
  }, [searchFiltered, hideDuplicates])

  // --- Infinite scroll ---

  const { items: visibleDecisions, hasMore, sentinelRef } = useInfiniteScroll({
    data: displayDecisions,
    pageSize: 50,
  })

  // --- Selection helpers ---

  const toggleSelected = useCallback((id: number) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }, [])

  const toggleSelectAll = useCallback(() => {
    if (selectedIds.size === visibleDecisions.length) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(visibleDecisions.map(d => d.id)))
    }
  }, [visibleDecisions, selectedIds.size])

  // Clear selection when data changes
  useEffect(() => {
    setSelectedIds(new Set())
  }, [decisionsData, searchQuery, hideDuplicates, hideExpired])

  // --- Delete handlers ---

  const handleDelete = async () => {
    if (!deleteId) return
    try {
      await api.crowdsec.deleteDecision({ id: deleteId.toString() })
      toast.success('Decision deleted successfully')
      refetch()
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } }
      toast.error(axiosError.response?.data?.error || 'Failed to delete decision')
    } finally {
      setDeleteId(null)
    }
  }

  const handleBulkDelete = async () => {
    if (selectedIds.size === 0) return
    setBulkDeleting(true)

    // When duplicates are collapsed, expand _ids for selected rows
    const idsToDelete: number[] = []
    if (hideDuplicates) {
      for (const row of displayDecisions) {
        if (selectedIds.has(row.id)) {
          idsToDelete.push(...row._ids)
        }
      }
    } else {
      idsToDelete.push(...selectedIds)
    }

    let deleted = 0
    let failed = 0
    for (const id of idsToDelete) {
      try {
        await api.crowdsec.deleteDecision({ id: id.toString() })
        deleted++
      } catch {
        failed++
      }
    }

    setBulkDeleting(false)
    setShowBulkDeleteConfirm(false)
    setSelectedIds(new Set())

    if (failed === 0) {
      toast.success(`Deleted ${deleted} decision${deleted !== 1 ? 's' : ''} successfully`)
    } else {
      toast.warning(`Deleted ${deleted}, failed ${failed}`)
    }
    refetch()
  }

  // --- Filter handlers ---

  const handleFilterChange = (key: string, value: string | boolean) => {
    setFilters(prev => ({ ...prev, [key]: value }))
  }

  const handleApplyFilters = () => {
    setActiveFilters(filters)
    toast.success('Filters applied')
  }

  const handleResetFilters = () => {
    setFilters({})
    setActiveFilters({})
    setSearchParams(new URLSearchParams(), { replace: true })
    toast.info('Filters reset')
  }

  // --- CSV export ---

  const handleExport = () => {
    if (!decisionsData?.decisions || decisionsData.decisions.length === 0) {
      toast.error('No data to export')
      return
    }
    const headers = ['ID', 'Alert ID', 'Type', 'Scope', 'Value', 'Origin', 'Scenario', 'Duration', 'Created At', 'Country', 'AS']
    const csvContent = [
      headers.map(escapeCSVField).join(','),
      ...decisionsData.decisions.map((d: Decision) => {
        const source = alertSourceMap.get(d.alert_id)
        return [d.id, d.alert_id, d.type, d.scope, d.value, d.origin, d.scenario, d.duration, d.created_at, source?.cn ?? '', source?.as_name ?? '']
          .map(escapeCSVField)
          .join(',')
      }),
    ].join('\n')
    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `crowdsec-decisions-${new Date().toISOString()}.csv`
    a.click()
    window.URL.revokeObjectURL(url)
    toast.success('Decisions exported successfully')
  }

  const totalCount = decisionsData?.count ?? 0

  return (
    <div className="space-y-6">
      <PageHeader
        title="Decision List Analysis"
        description="Advanced filtering and analysis of CrowdSec decisions"
        breadcrumbs="Activity / Decisions"
        actions={totalCount > 0 ? (
          <Badge variant="secondary">{totalCount} decisions</Badge>
        ) : undefined}
      />

      {isError && <QueryError error={error} onRetry={refetch} />}

      {decisionsData?.decisions && decisionsData.decisions.length > 0 && (
        <div className="grid gap-4 grid-cols-1 lg:grid-cols-3">
          <ChartCard title="Decisions Over Time" description="Decision creation timeline">
            <AreaTimeline
              data={decisionTimeData}
              height={250}
            />
          </ChartCard>
          <ChartCard title="Decision Types" description="Type distribution">
            <PieBreakdown
              data={decisionTypeData}
              height={250}
            />
          </ChartCard>
          <ChartCard title="Top IPs" description="Most targeted addresses">
            <BarDistribution
              data={topIPsData}
              height={250}
              layout="horizontal"
            />
          </ChartCard>
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Repeated Offenders (30d)</CardTitle>
          <CardDescription>
            Entities with 3 or more decisions in the last 30 days
          </CardDescription>
        </CardHeader>
        <CardContent>
          {repeatedOffendersData?.offenders && repeatedOffendersData.offenders.length > 0 ? (
            <div className="rounded-md border overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Value</TableHead>
                    <TableHead>Scope</TableHead>
                    <TableHead>Hits</TableHead>
                    <TableHead>First Seen</TableHead>
                    <TableHead>Last Seen</TableHead>
                    <TableHead>Last Notified</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {repeatedOffendersData.offenders.map((offender: RepeatedOffender) => (
                    <TableRow key={`${offender.value}-${offender.scope}`}>
                      <TableCell className="font-mono text-sm">{offender.value}</TableCell>
                      <TableCell><Badge variant="outline">{offender.scope}</Badge></TableCell>
                      <TableCell>{offender.hit_count}</TableCell>
                      <TableCell><TimeDisplay date={offender.first_decision_at} /></TableCell>
                      <TableCell><TimeDisplay date={offender.last_decision_at} /></TableCell>
                      <TableCell>
                        {offender.last_notified_at ? <TimeDisplay date={offender.last_notified_at} /> : 'Never'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="text-sm text-muted-foreground">No repeated offenders detected in the last 30 days.</div>
          )}
        </CardContent>
      </Card>

      <CrowdSecFilterForm
        fields={DECISION_FILTER_FIELDS}
        filters={filters}
        onFilterChange={handleFilterChange}
        onApply={handleApplyFilters}
        onReset={handleResetFilters}
        description="Apply filters to analyze specific decisions based on CrowdSec criteria"
        showIncludeAll
        includeAllLabel="Include decisions from Central API"
      />

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                Decision Results
                {totalCount > 0 && (
                  <Badge variant="secondary" className="text-xs font-normal">
                    {totalCount}
                  </Badge>
                )}
              </CardTitle>
              <CardDescription>
                {searchFiltered.length !== totalCount
                  ? `${searchFiltered.length} of ${totalCount} decisions shown`
                  : `${totalCount} decisions found`}
              </CardDescription>
            </div>
            <div className="flex gap-2 flex-wrap justify-end">
              {selectedIds.size > 0 && (
                <Button
                  variant="destructive"
                  size="sm"
                  disabled={bulkDeleting}
                  onClick={() => setShowBulkDeleteConfirm(true)}
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  Delete Selected ({selectedIds.size})
                </Button>
              )}
              <AddDecisionDialog onSuccess={refetch} />
              <ImportDecisionsDialog onSuccess={refetch} />
              <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isLoading}>
                <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
              <Button variant="outline" size="sm" onClick={handleExport}>
                <Download className="h-4 w-4 mr-2" />Export CSV
              </Button>
            </div>
          </div>

          {/* Search, hide-duplicates, and hide-expired controls */}
          <div className="flex items-center gap-4 pt-2 flex-wrap">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search by IP, scenario, origin..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value)
                  setQuery(e.target.value)
                }}
                className="pl-9"
              />
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id="hide-duplicates"
                checked={hideDuplicates}
                onCheckedChange={setHideDuplicates}
              />
              <label
                htmlFor="hide-duplicates"
                className="text-sm text-muted-foreground cursor-pointer select-none"
              >
                Hide duplicates
              </label>
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id="hide-expired"
                checked={hideExpired}
                onCheckedChange={setHideExpired}
              />
              <label
                htmlFor="hide-expired"
                className="text-sm text-muted-foreground cursor-pointer select-none"
              >
                Hide expired
              </label>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <ResultsSummary
            total={totalCount}
            filtered={searchFiltered.length}
            label="decisions"
            query={searchQuery || undefined}
          />
          {isLoading ? (
            <PageLoader message="Loading decisions..." />
          ) : visibleDecisions.length > 0 ? (
            <>
              <div className="rounded-md border overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-10">
                        <Checkbox
                          checked={visibleDecisions.length > 0 && selectedIds.size === visibleDecisions.length}
                          onCheckedChange={toggleSelectAll}
                          aria-label="Select all"
                        />
                      </TableHead>
                      <TableHead>ID</TableHead>
                      <TableHead>Alert</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Scope</TableHead>
                      <TableHead>Value</TableHead>
                      <TableHead>Country</TableHead>
                      <TableHead>AS</TableHead>
                      <TableHead>Origin</TableHead>
                      <TableHead>Scenario</TableHead>
                      <TableHead>Duration</TableHead>
                      <TableHead>Expires</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {visibleDecisions.map((decision, index) => {
                      const expired = isExpired(decision.until)
                      const source = alertSourceMap.get(decision.alert_id)

                      return (
                        <TableRow key={decision.id || index} className={expired ? 'opacity-60' : undefined}>
                          <TableCell>
                            <Checkbox
                              checked={selectedIds.has(decision.id)}
                              onCheckedChange={() => toggleSelected(decision.id)}
                              aria-label={`Select decision ${decision.id}`}
                            />
                          </TableCell>
                          <TableCell className="font-mono text-xs">{decision.id}</TableCell>
                          <TableCell>
                            <Link
                              to={`/alerts?id=${decision.alert_id}`}
                              className="inline-flex items-center gap-1 text-primary hover:underline font-mono text-xs"
                              title={`View alert #${decision.alert_id}`}
                            >
                              <Shield className="h-3.5 w-3.5" />
                              {decision.alert_id}
                            </Link>
                          </TableCell>
                          <TableCell>
                            <Badge variant={decision.type === 'ban' ? 'destructive' : 'default'}>{decision.type}</Badge>
                          </TableCell>
                          <TableCell><Badge variant="outline">{decision.scope}</Badge></TableCell>
                          <TableCell className="font-mono text-sm">
                            <span className="inline-flex items-center gap-1.5">
                              {decision.value}
                              {hideDuplicates && decision._count > 1 && (
                                <Badge variant="secondary" className="text-[10px] px-1 py-0">
                                  x{decision._count}
                                </Badge>
                              )}
                            </span>
                          </TableCell>
                          <TableCell>
                            <CountryFlag code={source?.cn} showName={false} />
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate" title={source?.as_name ?? undefined}>
                            {source?.as_name
                              ? <span>{source.as_number ? `AS${source.as_number} ` : ''}{source.as_name}</span>
                              : <span className="text-muted-foreground">-</span>
                            }
                          </TableCell>
                          <TableCell><Badge variant="secondary">{decision.origin}</Badge></TableCell>
                          <TableCell className="text-sm">
                            <ScenarioName scenario={decision.scenario} />
                          </TableCell>
                          <TableCell className="text-sm">
                            <span className="inline-flex items-center gap-1.5">
                              {formatDuration(decision.duration)}
                              {expired && (
                                <Badge variant="destructive" className="text-[10px] px-1 py-0">
                                  Expired
                                </Badge>
                              )}
                            </span>
                          </TableCell>
                          <TableCell className="text-sm">
                            {decision.until ? expiresIn(decision.until) : 'N/A'}
                          </TableCell>
                          <TableCell className="text-sm">
                            <TimeDisplay date={decision.created_at} />
                          </TableCell>
                          <TableCell className="text-right">
                            <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive" onClick={() => setDeleteId(decision.id)}>
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      )
                    })}
                  </TableBody>
                </Table>
              </div>
              {hasMore && (
                <div ref={sentinelRef as React.RefObject<HTMLDivElement>} className="flex justify-center py-4">
                  <span className="text-sm text-muted-foreground">Loading more...</span>
                </div>
              )}
            </>
          ) : (
            <EmptyState icon={AlertCircle} title="No decisions found" description="Try adjusting your filters or check back later" />
          )}
        </CardContent>
      </Card>

      <InfoCard title="Filter Information" description="Understanding decision list filters" items={DECISION_INFO_ITEMS} />

      {/* Single-delete confirmation */}
      <AlertDialog open={!!deleteId} onOpenChange={(open) => !open && setDeleteId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. This will permanently delete the decision
              #{deleteId} from CrowdSec.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Bulk-delete confirmation */}
      <AlertDialog open={showBulkDeleteConfirm} onOpenChange={setShowBulkDeleteConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {selectedIds.size} decision{selectedIds.size !== 1 ? 's' : ''}?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. The selected decisions will be permanently
              removed from CrowdSec.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={bulkDeleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleBulkDelete}
              disabled={bulkDeleting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {bulkDeleting ? 'Deleting...' : 'Delete All'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
