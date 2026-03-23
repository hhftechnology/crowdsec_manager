import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import {
  Target, Shield, AlertTriangle, Bell, ShieldAlert,
  RefreshCw, RotateCcw, ChevronLeft, ChevronRight,
  Search, X, Loader2,
} from 'lucide-react'
import api from '@/lib/api'
import type { DecisionHistoryRecord, AlertHistoryRecord, RepeatedOffender, HistoryStats, HistoryConfig } from '@/lib/api'
import { useSSE } from '@/hooks/useSSE'
import { useRepeatedOffenderToast } from '@/hooks/useRepeatedOffenderToast'
import { StatusCard } from '@/components/common/StatusCard'
import { PageHeader } from '@/components/common/PageHeader'
import { TimeDisplay } from '@/components/common/TimeDisplay'
import { ReapplyDecisionDialog } from '@/components/history/ReapplyDecisionDialog'
import { BulkReapplyDialog } from '@/components/history/BulkReapplyDialog'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from '@/components/ui/card'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'

// ─── Per-page options ───────────────────────────────────────────────────────
const PER_PAGE_OPTIONS = [50, 100, 150] as const
type PerPage = (typeof PER_PAGE_OPTIONS)[number]

// ─── Pagination bar ─────────────────────────────────────────────────────────
interface PaginationBarProps {
  page: number
  perPage: PerPage
  total: number
  count: number
  onPrev: () => void
  onNext: () => void
  onPerPage: (n: PerPage) => void
}

function PaginationBar({ page, perPage, total, count, onPrev, onNext, onPerPage }: PaginationBarProps) {
  const from = total === 0 ? 0 : page * perPage + 1
  const to = Math.min(page * perPage + count, total)
  const totalPages = Math.ceil(total / perPage) || 1

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-3 text-sm">
      <span className="text-muted-foreground">
        {total === 0 ? 'No records' : `Showing ${from}–${to} of ${total}`}
      </span>
      <div className="flex items-center gap-2">
        <span className="text-muted-foreground text-xs">Rows:</span>
        {PER_PAGE_OPTIONS.map((n) => (
          <Button
            key={n}
            variant={perPage === n ? 'secondary' : 'ghost'}
            size="sm"
            className="h-7 px-2 text-xs"
            onClick={() => onPerPage(n)}
          >
            {n}
          </Button>
        ))}
        <div className="flex items-center gap-1 ml-2">
          <Button variant="outline" size="icon" className="h-7 w-7" onClick={onPrev} disabled={page === 0}>
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <span className="text-muted-foreground text-xs px-1">
            {page + 1} / {totalPages}
          </span>
          <Button
            variant="outline"
            size="icon"
            className="h-7 w-7"
            onClick={onNext}
            disabled={page * perPage + count >= total}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Status badge ────────────────────────────────────────────────────────────
function StatusBadge({ isStale }: { isStale: boolean }) {
  return isStale
    ? <Badge variant="secondary" className="text-xs">Expired</Badge>
    : <Badge variant="default" className="bg-emerald-600/20 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 text-xs">Active</Badge>
}

// ─── Loading rows ─────────────────────────────────────────────────────────────
function LoadingRows({ cols }: { cols: number }) {
  return (
    <TableRow>
      <TableCell colSpan={cols} className="text-center text-muted-foreground py-8">
        <Loader2 className="h-4 w-4 animate-spin inline-block mr-2" />Loading…
      </TableCell>
    </TableRow>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function History() {
  const queryClient = useQueryClient()
  const { lastEvent } = useSSE('/api/events/sse')
  useRepeatedOffenderToast(lastEvent)

  // Retention config state
  const [retentionInput, setRetentionInput] = useState<string>('')
  const [retentionOpen, setRetentionOpen] = useState(false)

  // Decisions tab state
  const [decisionPage, setDecisionPage] = useState(0)
  const [decisionPerPage, setDecisionPerPage] = useState<PerPage>(50)
  const [decisionShowStale, setDecisionShowStale] = useState<boolean | undefined>(undefined)
  const [decisionValue, setDecisionValue] = useState('')
  const [decisionScenario, setDecisionScenario] = useState('')
  const [decisionSelected, setDecisionSelected] = useState<Set<number>>(new Set())
  const [reapplyRecord, setReapplyRecord] = useState<DecisionHistoryRecord | null>(null)
  const [bulkReapplyOpen, setBulkReapplyOpen] = useState(false)

  // Alerts tab state
  const [alertPage, setAlertPage] = useState(0)
  const [alertPerPage, setAlertPerPage] = useState<PerPage>(50)
  const [alertShowStale, setAlertShowStale] = useState<boolean | undefined>(undefined)
  const [alertValue, setAlertValue] = useState('')
  const [alertScenario, setAlertScenario] = useState('')

  // Memoised filter keys so useQuery key is stable
  const decisionFilters = useMemo(() => ({
    stale: decisionShowStale,
    value: decisionValue || undefined,
    scenario: decisionScenario || undefined,
    limit: decisionPerPage,
    offset: decisionPage * decisionPerPage,
  }), [decisionShowStale, decisionValue, decisionScenario, decisionPerPage, decisionPage])

  const alertFilters = useMemo(() => ({
    stale: alertShowStale,
    value: alertValue || undefined,
    scenario: alertScenario || undefined,
    limit: alertPerPage,
    offset: alertPage * alertPerPage,
  }), [alertShowStale, alertValue, alertScenario, alertPerPage, alertPage])

  // ── Queries ────────────────────────────────────────────────────────────────
  const statsQuery = useQuery<HistoryStats | undefined>({
    queryKey: ['history-stats'],
    queryFn: async () => {
      const res = await api.crowdsec.getHistoryStats()
      return res.data.data
    },
    refetchInterval: 60_000,
  })

  const configQuery = useQuery<HistoryConfig | undefined>({
    queryKey: ['history-config'],
    queryFn: async () => {
      const res = await api.crowdsec.getHistoryConfig()
      return res.data.data
    },
  })

  const decisionsQuery = useQuery<{ decisions: DecisionHistoryRecord[]; count: number; total: number } | undefined>({
    queryKey: ['decision-history', decisionFilters],
    queryFn: async () => {
      const res = await api.crowdsec.getDecisionHistory(decisionFilters)
      return res.data.data
    },
    refetchInterval: 60_000,
  })

  const alertsQuery = useQuery<{ alerts: AlertHistoryRecord[]; count: number; total: number } | undefined>({
    queryKey: ['alert-history', alertFilters],
    queryFn: async () => {
      const res = await api.crowdsec.getAlertHistory(alertFilters)
      return res.data.data
    },
    refetchInterval: 60_000,
  })

  const offendersQuery = useQuery<{ offenders: RepeatedOffender[]; count: number } | undefined>({
    queryKey: ['repeated-offenders'],
    queryFn: async () => {
      const res = await api.crowdsec.getRepeatedOffenders()
      return res.data.data
    },
    refetchInterval: 60_000,
  })

  // ── Mutations ──────────────────────────────────────────────────────────────
  const updateRetentionMutation = useMutation({
    mutationFn: (days: number) => api.crowdsec.updateHistoryConfig(days),
    onSuccess: () => {
      toast.success('Retention updated')
      queryClient.invalidateQueries({ queryKey: ['history-config'] })
      setRetentionOpen(false)
    },
    onError: () => toast.error('Failed to update retention'),
  })

  // ── Derived data ───────────────────────────────────────────────────────────
  const stats = statsQuery.data
  const config = configQuery.data
  const decisions = decisionsQuery.data?.decisions ?? []
  const decisionsTotal = decisionsQuery.data?.total ?? 0
  const alerts = alertsQuery.data?.alerts ?? []
  const alertsTotal = alertsQuery.data?.total ?? 0
  const offenders = offendersQuery.data?.offenders ?? []

  const selectedIds = Array.from(decisionSelected)

  function toggleDecision(id: number) {
    setDecisionSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function toggleAllDecisions() {
    if (decisionSelected.size === decisions.length) {
      setDecisionSelected(new Set())
    } else {
      setDecisionSelected(new Set(decisions.map((d) => d.id)))
    }
  }

  function resetDecisionFilters() {
    setDecisionPage(0)
    setDecisionShowStale(undefined)
    setDecisionValue('')
    setDecisionScenario('')
  }

  function resetAlertFilters() {
    setAlertPage(0)
    setAlertShowStale(undefined)
    setAlertValue('')
    setAlertScenario('')
  }

  function handleDecisionPerPage(n: PerPage) {
    setDecisionPerPage(n)
    setDecisionPage(0)
  }

  function handleAlertPerPage(n: PerPage) {
    setAlertPerPage(n)
    setAlertPage(0)
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="History"
        description="Year-long record of all decisions and alerts, even after removal from CrowdSec"
      />

      {/* ── Stats cards ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatusCard
          title="Total Decisions"
          value={statsQuery.isLoading ? '…' : (stats?.total_decisions ?? 0)}
          icon={Target}
          variant="default"
        />
        <StatusCard
          title="Active Decisions"
          value={statsQuery.isLoading ? '…' : (stats?.active_decisions ?? 0)}
          icon={Shield}
          variant="success"
          description="Currently in CrowdSec"
        />
        <StatusCard
          title="Total Alerts"
          value={statsQuery.isLoading ? '…' : (stats?.total_alerts ?? 0)}
          icon={AlertTriangle}
          variant="default"
        />
        <StatusCard
          title="Active Alerts"
          value={statsQuery.isLoading ? '…' : (stats?.active_alerts ?? 0)}
          icon={Bell}
          variant="warning"
          description="Not yet removed"
        />
        <StatusCard
          title="Repeat Offenders"
          value={statsQuery.isLoading ? '…' : (stats?.repeated_offender_count ?? 0)}
          icon={ShieldAlert}
          variant="error"
          description="3+ hits in 30 days"
        />
      </div>

      {/* ── Retention config ───────────────────────────────────────────── */}
      <Card>
        <CardHeader
          className="cursor-pointer select-none flex flex-row items-center justify-between py-3"
          onClick={() => {
            setRetentionOpen((o) => !o)
            if (!retentionOpen && config) setRetentionInput(String(config.retention_days))
          }}
        >
          <div>
            <CardTitle className="text-sm">Retention Policy</CardTitle>
            {config && (
              <CardDescription className="text-xs">
                Currently retaining {config.retention_days} day{config.retention_days !== 1 ? 's' : ''} of history
              </CardDescription>
            )}
          </div>
          <span className="text-muted-foreground text-xs">{retentionOpen ? '▲' : '▼'}</span>
        </CardHeader>
        {retentionOpen && (
          <CardContent className="pt-0 pb-4">
            <div className="flex items-end gap-3">
              <div className="space-y-1">
                <Label htmlFor="retention-days" className="text-xs">Retention days (1–365)</Label>
                <Input
                  id="retention-days"
                  type="number"
                  min={1}
                  max={365}
                  className="w-28"
                  value={retentionInput}
                  onChange={(e) => setRetentionInput(e.target.value)}
                />
              </div>
              <Button
                size="sm"
                disabled={updateRetentionMutation.isPending}
                onClick={() => {
                  const days = parseInt(retentionInput)
                  if (isNaN(days) || days < 1 || days > 365) {
                    toast.error('Retention must be between 1 and 365 days')
                    return
                  }
                  updateRetentionMutation.mutate(days)
                }}
              >
                {updateRetentionMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
                Save
              </Button>
            </div>
          </CardContent>
        )}
      </Card>

      {/* ── Tabs ──────────────────────────────────────────────────────── */}
      <Tabs defaultValue="decisions">
        <TabsList>
          <TabsTrigger value="decisions">
            Decisions
            {decisionsTotal > 0 && <Badge variant="secondary" className="ml-2 text-xs">{decisionsTotal}</Badge>}
          </TabsTrigger>
          <TabsTrigger value="alerts">
            Alerts
            {alertsTotal > 0 && <Badge variant="secondary" className="ml-2 text-xs">{alertsTotal}</Badge>}
          </TabsTrigger>
          <TabsTrigger value="offenders">
            Repeated Offenders
            {offenders.length > 0 && <Badge variant="destructive" className="ml-2 text-xs">{offenders.length}</Badge>}
          </TabsTrigger>
        </TabsList>

        {/* ── Decisions tab ─────────────────────────────────────────── */}
        <TabsContent value="decisions" className="space-y-3 mt-4">
          {/* Filters */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="IP / value"
                value={decisionValue}
                onChange={(e) => { setDecisionValue(e.target.value); setDecisionPage(0) }}
                className="pl-8 w-44"
              />
            </div>
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Scenario"
                value={decisionScenario}
                onChange={(e) => { setDecisionScenario(e.target.value); setDecisionPage(0) }}
                className="pl-8 w-52"
              />
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id="d-show-stale"
                checked={decisionShowStale === true}
                onCheckedChange={(v) => { setDecisionShowStale(v ? true : undefined); setDecisionPage(0) }}
              />
              <Label htmlFor="d-show-stale" className="text-sm cursor-pointer">Show expired only</Label>
            </div>
            {(decisionValue || decisionScenario || decisionShowStale !== undefined) && (
              <Button variant="ghost" size="sm" onClick={resetDecisionFilters} className="gap-1">
                <X className="h-3 w-3" /> Reset
              </Button>
            )}
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 ml-auto"
              onClick={() => queryClient.invalidateQueries({ queryKey: ['decision-history'] })}
              title="Refresh"
            >
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>

          {/* Bulk action toolbar */}
          {decisionSelected.size > 0 && (
            <div className="flex items-center gap-3 rounded-md border bg-muted/40 px-3 py-2 text-sm">
              <span className="font-medium">{decisionSelected.size} selected</span>
              <Button size="sm" variant="outline" onClick={() => setBulkReapplyOpen(true)} className="gap-1">
                <RotateCcw className="h-3 w-3" /> Bulk Re-apply
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setDecisionSelected(new Set())}>
                Clear selection
              </Button>
            </div>
          )}

          {/* Table */}
          <div className="rounded-xl border bg-card overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-10">
                    <Checkbox
                      checked={decisions.length > 0 && decisionSelected.size === decisions.length}
                      onCheckedChange={toggleAllDecisions}
                      aria-label="Select all"
                    />
                  </TableHead>
                  <TableHead>Value / IP</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Scenario</TableHead>
                  <TableHead>Origin</TableHead>
                  <TableHead>First Seen</TableHead>
                  <TableHead>Last Seen</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {decisionsQuery.isLoading ? (
                  <LoadingRows cols={10} />
                ) : decisions.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={10} className="text-center text-muted-foreground py-8">
                      No decision history found
                    </TableCell>
                  </TableRow>
                ) : (
                  decisions.map((d: DecisionHistoryRecord) => (
                    <TableRow key={d.id} className={decisionSelected.has(d.id) ? 'bg-muted/30' : ''}>
                      <TableCell>
                        <Checkbox
                          checked={decisionSelected.has(d.id)}
                          onCheckedChange={() => toggleDecision(d.id)}
                          aria-label={`Select ${d.value}`}
                        />
                      </TableCell>
                      <TableCell className="font-mono text-sm">{d.value}</TableCell>
                      <TableCell className="text-muted-foreground text-xs">{d.scope}</TableCell>
                      <TableCell>
                        <Badge variant={d.type === 'ban' ? 'destructive' : 'secondary'} className="text-xs">
                          {d.type}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs max-w-[160px] truncate" title={d.scenario}>{d.scenario}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{d.origin}</TableCell>
                      <TableCell><TimeDisplay date={d.first_seen_at} /></TableCell>
                      <TableCell><TimeDisplay date={d.last_seen_at} /></TableCell>
                      <TableCell><StatusBadge isStale={d.is_stale} /></TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 gap-1 text-xs"
                          onClick={() => setReapplyRecord(d)}
                        >
                          <RotateCcw className="h-3 w-3" /> Re-apply
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          <PaginationBar
            page={decisionPage}
            perPage={decisionPerPage}
            total={decisionsTotal}
            count={decisions.length}
            onPrev={() => setDecisionPage((p) => Math.max(0, p - 1))}
            onNext={() => setDecisionPage((p) => p + 1)}
            onPerPage={handleDecisionPerPage}
          />
        </TabsContent>

        {/* ── Alerts tab ────────────────────────────────────────────── */}
        <TabsContent value="alerts" className="space-y-3 mt-4">
          {/* Filters */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="IP / value"
                value={alertValue}
                onChange={(e) => { setAlertValue(e.target.value); setAlertPage(0) }}
                className="pl-8 w-44"
              />
            </div>
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Scenario"
                value={alertScenario}
                onChange={(e) => { setAlertScenario(e.target.value); setAlertPage(0) }}
                className="pl-8 w-52"
              />
            </div>
            <div className="flex items-center gap-2">
              <Switch
                id="a-show-stale"
                checked={alertShowStale === true}
                onCheckedChange={(v) => { setAlertShowStale(v ? true : undefined); setAlertPage(0) }}
              />
              <Label htmlFor="a-show-stale" className="text-sm cursor-pointer">Show expired only</Label>
            </div>
            {(alertValue || alertScenario || alertShowStale !== undefined) && (
              <Button variant="ghost" size="sm" onClick={resetAlertFilters} className="gap-1">
                <X className="h-3 w-3" /> Reset
              </Button>
            )}
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 ml-auto"
              onClick={() => queryClient.invalidateQueries({ queryKey: ['alert-history'] })}
              title="Refresh"
            >
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>

          {/* Table */}
          <div className="rounded-xl border bg-card overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Value / IP</TableHead>
                  <TableHead>Scenario</TableHead>
                  <TableHead>Events</TableHead>
                  <TableHead>Origin</TableHead>
                  <TableHead>Start</TableHead>
                  <TableHead>Last Seen</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {alertsQuery.isLoading ? (
                  <LoadingRows cols={7} />
                ) : alerts.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                      No alert history found
                    </TableCell>
                  </TableRow>
                ) : (
                  alerts.map((a: AlertHistoryRecord) => (
                    <TableRow key={a.id}>
                      <TableCell className="font-mono text-sm">{a.value}</TableCell>
                      <TableCell className="text-xs max-w-[160px] truncate" title={a.scenario}>{a.scenario}</TableCell>
                      <TableCell>
                        {a.events_count > 0 && (
                          <Badge variant="outline" className="text-xs">{a.events_count}</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{a.origin}</TableCell>
                      <TableCell>
                        {a.start_at
                          ? <TimeDisplay date={a.start_at} />
                          : <span className="text-muted-foreground">-</span>
                        }
                      </TableCell>
                      <TableCell><TimeDisplay date={a.last_seen_at} /></TableCell>
                      <TableCell><StatusBadge isStale={a.is_stale} /></TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          <PaginationBar
            page={alertPage}
            perPage={alertPerPage}
            total={alertsTotal}
            count={alerts.length}
            onPrev={() => setAlertPage((p) => Math.max(0, p - 1))}
            onNext={() => setAlertPage((p) => p + 1)}
            onPerPage={handleAlertPerPage}
          />
        </TabsContent>

        {/* ── Repeated Offenders tab ────────────────────────────────── */}
        <TabsContent value="offenders" className="space-y-3 mt-4">
          <div className="rounded-xl border bg-card overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Value / IP</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Hit Count</TableHead>
                  <TableHead>Window</TableHead>
                  <TableHead>First Decision</TableHead>
                  <TableHead>Last Decision</TableHead>
                  <TableHead>Last Notified</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {offendersQuery.isLoading ? (
                  <LoadingRows cols={8} />
                ) : offenders.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center text-muted-foreground py-8">
                      No repeated offenders detected
                    </TableCell>
                  </TableRow>
                ) : (
                  offenders.map((o: RepeatedOffender, idx: number) => (
                    <TableRow key={`${o.value}-${idx}`}>
                      <TableCell className="font-mono text-sm">{o.value}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{o.scope}</TableCell>
                      <TableCell>
                        <Badge variant="destructive" className="text-xs">{o.hit_count}</Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{o.window_days}d</TableCell>
                      <TableCell><TimeDisplay date={o.first_decision_at} /></TableCell>
                      <TableCell><TimeDisplay date={o.last_decision_at} /></TableCell>
                      <TableCell>
                        {o.last_notified_at
                          ? <TimeDisplay date={o.last_notified_at} />
                          : <span className="text-muted-foreground text-xs">-</span>
                        }
                      </TableCell>
                      <TableCell className="text-right" />
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </TabsContent>
      </Tabs>

      {/* ── Dialogs ──────────────────────────────────────────────────── */}
      <ReapplyDecisionDialog
        record={reapplyRecord}
        open={reapplyRecord !== null}
        onClose={() => setReapplyRecord(null)}
        onSuccess={() => {
          queryClient.invalidateQueries({ queryKey: ['decision-history'] })
          queryClient.invalidateQueries({ queryKey: ['history-stats'] })
        }}
      />

      <BulkReapplyDialog
        ids={selectedIds}
        open={bulkReapplyOpen}
        onClose={() => setBulkReapplyOpen(false)}
        onSuccess={() => {
          setDecisionSelected(new Set())
          queryClient.invalidateQueries({ queryKey: ['decision-history'] })
          queryClient.invalidateQueries({ queryKey: ['history-stats'] })
        }}
      />
    </div>
  )
}
