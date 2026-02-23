import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { Decision } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { RefreshCw, AlertCircle, Download, Trash2 } from 'lucide-react'
import { AddDecisionDialog } from '@/components/decisions/AddDecisionDialog'
import { ImportDecisionsDialog } from '@/components/decisions/ImportDecisionsDialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { PageHeader, EmptyState, PageLoader, InfoCard, CrowdSecFilterForm, SCOPE_OPTIONS, TYPE_OPTIONS, ORIGIN_OPTIONS } from '@/components/common'
import type { FilterField } from '@/components/common'
import { ChartCard, AreaTimeline, PieBreakdown, BarDistribution } from '@/components/charts'
import { groupByField } from '@/lib/chart-utils'

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

export default function DecisionAnalysis() {
  const [filters, setFilters] = useState<DecisionFilters>({})
  const [activeFilters, setActiveFilters] = useState<DecisionFilters>({})
  const [deleteId, setDeleteId] = useState<number | null>(null)

  const { data: decisionsData, isLoading, refetch } = useQuery({
    queryKey: ['decisions-analysis', activeFilters],
    queryFn: async () => {
      const response = await api.crowdsec.getDecisionsAnalysis(activeFilters)
      return response.data.data
    },
    refetchInterval: 30000,
  })

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

  const handleDelete = async () => {
    if (!deleteId) return
    try {
      await api.crowdsec.deleteDecision({ id: deleteId.toString() })
      toast.success('Decision deleted successfully')
      refetch()
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } }
      toast.error(axiosError.response?.data?.error || 'Failed to delete decision')
    } finally {
      setDeleteId(null)
    }
  }

  const handleFilterChange = (key: string, value: string | boolean) => {
    setFilters({ ...filters, [key]: value })
  }

  const handleExport = () => {
    if (!decisionsData?.decisions || decisionsData.decisions.length === 0) {
      toast.error('No data to export')
      return
    }
    const csvContent = [
      ['ID', 'Alert ID', 'Type', 'Scope', 'Value', 'Origin', 'Scenario', 'Duration', 'Created At'].join(','),
      ...decisionsData.decisions.map((d: Decision) =>
        [d.id, d.alert_id, d.type, d.scope, d.value, d.origin, d.scenario, d.duration, d.created_at].join(',')
      ),
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

  return (
    <div className="space-y-6">
      <PageHeader
        title="Decision List Analysis"
        description="Advanced filtering and analysis of CrowdSec decisions"
      />

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

      <CrowdSecFilterForm
        fields={DECISION_FILTER_FIELDS}
        filters={filters}
        onFilterChange={handleFilterChange}
        onApply={() => { setActiveFilters(filters); toast.success('Filters applied') }}
        onReset={() => { setFilters({}); setActiveFilters({}); toast.info('Filters reset') }}
        description="Apply filters to analyze specific decisions based on CrowdSec criteria"
        showIncludeAll
        includeAllLabel="Include decisions from Central API"
      />

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Decision Results</CardTitle>
              <CardDescription>{decisionsData?.count || 0} decisions found</CardDescription>
            </div>
            <div className="flex gap-2">
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
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <PageLoader message="Loading decisions..." />
          ) : decisionsData?.decisions && decisionsData.decisions.length > 0 ? (
            <div className="rounded-md border overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ID</TableHead>
                    <TableHead>Alert ID</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Scope</TableHead>
                    <TableHead>Value</TableHead>
                    <TableHead>Origin</TableHead>
                    <TableHead>Scenario</TableHead>
                    <TableHead>Duration</TableHead>
                    <TableHead>Expires</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {decisionsData.decisions.map((decision: Decision, index: number) => (
                    <TableRow key={decision.id || index}>
                      <TableCell className="font-mono text-xs">{decision.id}</TableCell>
                      <TableCell className="font-mono text-xs">{decision.alert_id}</TableCell>
                      <TableCell>
                        <Badge variant={decision.type === 'ban' ? 'destructive' : 'default'}>{decision.type}</Badge>
                      </TableCell>
                      <TableCell><Badge variant="outline">{decision.scope}</Badge></TableCell>
                      <TableCell className="font-mono text-sm">{decision.value}</TableCell>
                      <TableCell><Badge variant="secondary">{decision.origin}</Badge></TableCell>
                      <TableCell className="text-sm">{decision.scenario}</TableCell>
                      <TableCell className="text-sm">{decision.duration}</TableCell>
                      <TableCell className="text-sm">
                        {decision.until ? new Date(decision.until).toLocaleString() : 'N/A'}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive" onClick={() => setDeleteId(decision.id)}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <EmptyState icon={AlertCircle} title="No decisions found" description="Try adjusting your filters or check back later" />
          )}
        </CardContent>
      </Card>

      <InfoCard title="Filter Information" description="Understanding decision list filters" items={DECISION_INFO_ITEMS} />

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
    </div>
  )
}
