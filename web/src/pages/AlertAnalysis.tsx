import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { CrowdSecAlert } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { RefreshCw, AlertCircle, Download } from 'lucide-react'
import { PageHeader, EmptyState, PageLoader, InfoCard, CrowdSecFilterForm, SCOPE_OPTIONS, TYPE_OPTIONS, ORIGIN_OPTIONS, QueryError } from '@/components/common'
import type { FilterField } from '@/components/common'
import { AlertCard } from '@/components/alerts/AlertCard'
import { ChartCard, AreaTimeline, BarDistribution } from '@/components/charts'
import { groupByField } from '@/lib/chart-utils'

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

export default function AlertAnalysis() {
  const [filters, setFilters] = useState<AlertFilters>({})
  const [activeFilters, setActiveFilters] = useState<AlertFilters>({})
  const [expandedAlert, setExpandedAlert] = useState<number | null>(null)

  const { data: alertsData, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['alerts-analysis', activeFilters],
    queryFn: async () => {
      const response = await api.crowdsec.getAlertsAnalysis(activeFilters)
      return response.data.data
    },
    refetchInterval: 30000,
  })

  const alertTimeData = useMemo(() => {
    if (!alertsData?.alerts) return []
    const buckets: Record<string, number> = {}
    for (const a of alertsData.alerts) {
      const date = new Date(a.start_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
      buckets[date] = (buckets[date] || 0) + 1
    }
    return Object.entries(buckets).map(([date, count]) => ({ date, value: count }))
  }, [alertsData])

  const scenarioData = useMemo(() => {
    if (!alertsData?.alerts) return []
    return groupByField(alertsData.alerts, 'scenario', 8)
  }, [alertsData])

  const handleApplyFilters = () => {
    setActiveFilters(filters)
    toast.success('Filters applied')
  }

  const handleResetFilters = () => {
    setFilters({})
    setActiveFilters({})
    toast.info('Filters reset')
  }

  const handleFilterChange = (key: string, value: string | boolean) => {
    setFilters({ ...filters, [key]: value })
  }

  const handleExport = () => {
    if (!alertsData?.alerts || alertsData.alerts.length === 0) {
      toast.error('No data to export')
      return
    }
    const csvContent = [
      ['ID', 'Scenario', 'Scope', 'Value', 'Origin', 'Type', 'Events Count', 'Start At', 'Stop At'].join(','),
      ...alertsData.alerts.map((a: CrowdSecAlert) =>
        [a.id, a.scenario, a.scope, a.value, a.origin, a.type || 'N/A', a.events_count || 0, a.start_at, a.stop_at || 'Ongoing'].join(',')
      ),
    ].join('\n')
    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `crowdsec-alerts-${new Date().toISOString()}.csv`
    a.click()
    window.URL.revokeObjectURL(url)
    toast.success('Alerts exported successfully')
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Alert List Analysis"
        description="Advanced filtering and analysis of CrowdSec alerts"
      />

      {isError && <QueryError error={error} onRetry={refetch} />}

      {alertsData?.alerts && alertsData.alerts.length > 0 && (
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
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Alert Results</CardTitle>
              <CardDescription>{alertsData?.count || 0} alerts found</CardDescription>
            </div>
            <div className="flex gap-2">
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
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <PageLoader message="Loading alerts..." />
          ) : alertsData?.alerts && alertsData.alerts.length > 0 ? (
            <div className="space-y-2">
              {alertsData.alerts.map((alert: CrowdSecAlert, index: number) => (
                <AlertCard
                  key={alert.id || index}
                  alert={alert}
                  index={index}
                  isExpanded={expandedAlert === index}
                  onToggle={() => setExpandedAlert(expandedAlert === index ? null : index)}
                />
              ))}
            </div>
          ) : (
            <EmptyState
              icon={AlertCircle}
              title="No alerts found"
              description="Try adjusting your filters or check back later"
            />
          )}
        </CardContent>
      </Card>

      <InfoCard
        title="Filter Information"
        description="Understanding alert list filters"
        items={ALERT_INFO_ITEMS}
      />
    </div>
  )
}
