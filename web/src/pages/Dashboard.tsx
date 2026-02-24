import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import api, { Container as ContainerType, Decision, CrowdSecAlert } from '@/lib/api'
import { PageHeader, QueryError, ScenarioName } from '@/components/common'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Shield, Users, Container, Activity, AlertTriangle, RefreshCw } from 'lucide-react'
import { StatCard, ChartCard, AreaTimeline, PieBreakdown, BarDistribution } from '@/components/charts'
import { groupByField, CHART_COLORS } from '@/lib/chart-utils'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'

interface ActivityBucket {
  date: string
  alerts: number
  decisions: number
}

function getThresholdBorder(value: number, greenMax: number, yellowMax: number): string {
  if (value < greenMax) return 'border-l-4 border-l-green-500'
  if (value < yellowMax) return 'border-l-4 border-l-yellow-500'
  return 'border-l-4 border-l-red-500'
}

export default function Dashboard() {
  const navigate = useNavigate()

  const { data: healthData, isLoading: healthLoading, isError, error, refetch: refetchHealth, dataUpdatedAt: healthUpdatedAt } = useQuery({
    queryKey: ['health'],
    queryFn: async () => {
      const response = await api.health.checkStack()
      return response.data.data
    },
    refetchInterval: 5000,
  })

  const { data: decisionsData, isLoading: decisionsLoading, dataUpdatedAt: decisionsUpdatedAt } = useQuery({
    queryKey: ['decisions'],
    queryFn: async () => {
      const response = await api.crowdsec.getDecisions()
      return response.data.data
    },
    refetchInterval: 10000,
  })

  const { data: bouncersData, isLoading: bouncersLoading, dataUpdatedAt: bouncersUpdatedAt } = useQuery({
    queryKey: ['bouncers'],
    queryFn: async () => {
      const response = await api.crowdsec.getBouncers()
      return response.data.data
    },
    refetchInterval: 30000,
  })

  const { data: alertsData, dataUpdatedAt: alertsUpdatedAt } = useQuery({
    queryKey: ['alerts-dashboard'],
    queryFn: async () => {
      const response = await api.crowdsec.getAlertsAnalysis({ since: '7d' })
      return response.data.data
    },
    refetchInterval: 30000,
  })

  const lastUpdated = useMemo(() => {
    const timestamps = [healthUpdatedAt, decisionsUpdatedAt, bouncersUpdatedAt, alertsUpdatedAt].filter(Boolean)
    if (timestamps.length === 0) return null
    return new Date(Math.max(...timestamps))
  }, [healthUpdatedAt, decisionsUpdatedAt, bouncersUpdatedAt, alertsUpdatedAt])

  const lastUpdatedLabel = lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : 'Not refreshed yet'

  const decisions: Decision[] = useMemo(() => {
    if (!decisionsData) return []
    if (Array.isArray(decisionsData.decisions)) return decisionsData.decisions
    return []
  }, [decisionsData])

  const decisionsCount = useMemo(() => {
    if (!decisionsData) return 0
    if (typeof decisionsData.count === 'number') return decisionsData.count
    return decisions.length
  }, [decisionsData, decisions])

  const bouncersCount = useMemo(() => {
    if (!bouncersData) return 0
    if (typeof bouncersData.count === 'number') return bouncersData.count
    if (Array.isArray(bouncersData.bouncers)) return bouncersData.bouncers.length
    return 0
  }, [bouncersData])

  const runningContainers = healthData?.containers?.filter((c: ContainerType) => c.running).length ?? 0
  const totalContainers = healthData?.containers?.length ?? 0

  const alerts: CrowdSecAlert[] = useMemo(() => {
    if (!alertsData) return []
    if (Array.isArray(alertsData.alerts)) return alertsData.alerts
    if (Array.isArray(alertsData)) return alertsData
    return []
  }, [alertsData])

  const alertsCount = alertsData?.count ?? alerts.length

  const decisionTypeData = useMemo(() => {
    if (decisions.length === 0) return []
    return groupByField(decisions, 'type', 5)
  }, [decisions])

  const topBlockedIPs = useMemo(() => {
    if (decisions.length === 0) return []
    return groupByField(decisions, 'value', 10)
  }, [decisions])

  const decisionsOverTime = useMemo(() => {
    if (decisions.length === 0) return []
    const buckets: Record<string, number> = {}
    for (const d of decisions) {
      const date = d.created_at
        ? new Date(d.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
        : 'Unknown'
      buckets[date] = (buckets[date] || 0) + 1
    }
    return Object.entries(buckets)
      .map(([date, count]) => ({ date, value: count }))
      .slice(-7)
  }, [decisions])

  const combinedActivityData = useMemo<ActivityBucket[]>(() => {
    const now = new Date()
    const buckets: Record<string, ActivityBucket> = {}

    // Initialize last 7 days
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now)
      d.setDate(d.getDate() - i)
      const key = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
      buckets[key] = { date: key, alerts: 0, decisions: 0 }
    }

    // Bucket alerts
    for (const alert of alerts) {
      const dateKey = new Date(alert.start_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
      if (buckets[dateKey]) {
        buckets[dateKey].alerts += 1
      }
    }

    // Bucket decisions
    for (const decision of decisions) {
      if (!decision.created_at) continue
      const dateKey = new Date(decision.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
      if (buckets[dateKey]) {
        buckets[dateKey].decisions += 1
      }
    }

    return Object.values(buckets)
  }, [alerts, decisions])

  const topScenarios = useMemo(() => {
    if (alerts.length === 0) return []
    return groupByField(alerts, 'scenario', 5)
  }, [alerts])

  const lastUpdatedAt = useMemo(() => {
    const timestamps = [healthUpdatedAt, decisionsUpdatedAt, bouncersUpdatedAt, alertsUpdatedAt].filter(Boolean)
    if (timestamps.length === 0) return null
    return Math.max(...timestamps)
  }, [healthUpdatedAt, decisionsUpdatedAt, bouncersUpdatedAt, alertsUpdatedAt])

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description="System overview, activity, and key metrics"
        actions={<span className="text-xs text-muted-foreground">{lastUpdatedLabel}</span>}
      />
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground mt-1">
          System overview and threat posture
        </p>
      </div>

      {/* Connection error banner */}
      {isError && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            Unable to connect to backend. Check if the server is running.
          </AlertDescription>
        </Alert>
      )}

      {isError && <QueryError error={error} onRetry={refetchHealth} />}

      {/* Row 1: Stat Cards */}
      <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
        <div className="cursor-pointer" onClick={() => navigate('/decisions')}>
          <StatCard
            title="Active Decisions"
            value={decisionsCount}
            description="IPs currently blocked"
            icon={<Shield className="h-4 w-4 text-muted-foreground" />}
            loading={decisionsLoading}
            className={!decisionsLoading ? getThresholdBorder(decisionsCount, 50, 100) : undefined}
          />
        </div>
        <div className="cursor-pointer" onClick={() => navigate('/alerts')}>
          <StatCard
            title="Alerts (7d)"
            value={alertsCount}
            description="Alerts in the last 7 days"
            icon={<Activity className="h-4 w-4 text-muted-foreground" />}
            loading={!alertsData && !decisionsLoading}
            className={alertsData ? getThresholdBorder(alertsCount, 20, 50) : undefined}
          />
        </div>
        <div className="cursor-pointer" onClick={() => navigate('/bouncers')}>
          <StatCard
            title="Active Bouncers"
            value={bouncersCount}
            description="Connected enforcement agents"
            icon={<Users className="h-4 w-4 text-muted-foreground" />}
            loading={bouncersLoading}
          />
        </div>
        <div className="cursor-pointer" onClick={() => navigate('/health')}>
          <StatCard
            title="Containers"
            value={`${runningContainers}/${totalContainers}`}
            description={healthData?.allRunning ? 'All running' : 'Some containers down'}
            icon={<Container className="h-4 w-4 text-muted-foreground" />}
            loading={healthLoading}
          />
        </div>
      </div>

      {/* Row 2: Combined Activity History */}
      <ChartCard title="Activity History (7d)" description="Alerts and decisions over the last 7 days">
        {combinedActivityData.some((b) => b.alerts > 0 || b.decisions > 0) ? (
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={combinedActivityData}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis dataKey="date" className="text-xs" tick={{ fontSize: 12 }} />
              <YAxis allowDecimals={false} className="text-xs" tick={{ fontSize: 12 }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'hsl(var(--popover))',
                  borderColor: 'hsl(var(--border))',
                  borderRadius: '0.5rem',
                  color: 'hsl(var(--popover-foreground))',
                }}
              />
              <Legend />
              <Bar dataKey="alerts" name="Alerts" fill={CHART_COLORS[0]} radius={[4, 4, 0, 0]} />
              <Bar dataKey="decisions" name="Decisions" fill={CHART_COLORS[1]} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-72 text-muted-foreground text-sm">
            No activity data available
          </div>
        )}
      </ChartCard>

      {/* Row 3: Decisions Over Time + Type Distribution */}
      <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
        <ChartCard title="Decisions Over Time" description="Recent decision activity">
          {decisionsOverTime.length > 0 ? (
            <AreaTimeline data={decisionsOverTime} height={280} />
          ) : (
            <div className="flex items-center justify-center h-72 text-muted-foreground text-sm">
              No decision data available
            </div>
          )}
        </ChartCard>
        <ChartCard title="Decision Types" description="Distribution by type">
          {decisionTypeData.length > 0 ? (
            <PieBreakdown data={decisionTypeData} height={280} />
          ) : (
            <div className="flex items-center justify-center h-72 text-muted-foreground text-sm">
              No decision data available
            </div>
          )}
        </ChartCard>
      </div>

      {/* Row 4: Top Scenarios + Top Blocked IPs */}
      <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
        {/* Top Scenarios */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Shield className="h-5 w-5" />
              Top Scenarios (7d)
            </CardTitle>
          </CardHeader>
          <CardContent>
            {topScenarios.length > 0 ? (
              <div className="space-y-3">
                {topScenarios.map((item) => (
                  <div key={item.name} className="flex items-center justify-between">
                    <ScenarioName scenario={item.name} />
                    <Badge variant="secondary" className="tabular-nums">
                      {item.value}
                    </Badge>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-muted-foreground text-sm text-center py-4">
                No scenario data available
              </p>
            )}
          </CardContent>
        </Card>

        {/* Top Blocked IPs */}
        {topBlockedIPs.length > 0 ? (
          <ChartCard title="Top Blocked IPs" description="Most frequently targeted addresses">
            <BarDistribution data={topBlockedIPs} height={300} layout="horizontal" />
          </ChartCard>
        ) : (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Top Blocked IPs</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground text-sm text-center py-4">
                No blocked IP data available
              </p>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Row 5: Container Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Container className="h-5 w-5" />
            Container Status
          </CardTitle>
        </CardHeader>
        <CardContent>
          {healthLoading ? (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-14 animate-pulse bg-muted rounded-lg" />
              ))}
            </div>
          ) : healthData?.containers ? (
            <div className="space-y-2">
              {healthData.containers.map((container: ContainerType) => (
                <div
                  key={container.id}
                  className="flex items-center justify-between p-3 rounded-lg border"
                >
                  <div className="flex items-center gap-3">
                    <div className={`h-2 w-2 rounded-full ${container.running ? 'bg-green-500' : 'bg-red-500'}`} />
                    <div>
                      <p className="font-medium">{container.name}</p>
                      <p className="text-sm text-muted-foreground">
                        {container.id.substring(0, 12)}
                      </p>
                    </div>
                  </div>
                  <Badge variant={container.running ? 'success' : 'destructive'}>
                    {container.status}
                  </Badge>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-muted-foreground text-sm text-center py-4">No container data available</p>
          )}
        </CardContent>
      </Card>

      {/* Auto-refresh indicator */}
      <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground">
        <RefreshCw className="h-3 w-3" />
        {lastUpdatedAt ? (
          <span>
            Last updated: {new Date(lastUpdatedAt).toLocaleTimeString()} — Auto-refreshing every 5-30s
          </span>
        ) : (
          <span>Auto-refreshing every 5-30s</span>
        )}
      </div>
    </div>
  )
}
