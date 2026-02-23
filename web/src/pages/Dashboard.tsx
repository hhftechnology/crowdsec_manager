import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import api, { Container as ContainerType, Decision } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Shield, Users, Container, Activity } from 'lucide-react'
import { StatCard, ChartCard, AreaTimeline, PieBreakdown, BarDistribution } from '@/components/charts'
import { groupByField } from '@/lib/chart-utils'

export default function Dashboard() {
  const { data: healthData, isLoading: healthLoading } = useQuery({
    queryKey: ['health'],
    queryFn: async () => {
      const response = await api.health.checkStack()
      return response.data.data
    },
    refetchInterval: 5000,
  })

  const { data: decisionsData, isLoading: decisionsLoading } = useQuery({
    queryKey: ['decisions'],
    queryFn: async () => {
      const response = await api.crowdsec.getDecisions()
      return response.data.data
    },
    refetchInterval: 10000,
  })

  const { data: bouncersData, isLoading: bouncersLoading } = useQuery({
    queryKey: ['bouncers'],
    queryFn: async () => {
      const response = await api.crowdsec.getBouncers()
      return response.data.data
    },
    refetchInterval: 30000,
  })

  const { data: alertsData } = useQuery({
    queryKey: ['alerts-dashboard'],
    queryFn: async () => {
      const response = await api.crowdsec.getAlertsAnalysis({ since: '7d' })
      return response.data.data
    },
    refetchInterval: 30000,
  })

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
  const alertsCount = alertsData?.count ?? 0

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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground mt-1">
          System overview and threat posture
        </p>
      </div>

      {/* Row 1: Stat Cards */}
      <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Active Decisions"
          value={decisionsCount}
          description="IPs currently blocked"
          icon={<Shield className="h-4 w-4 text-muted-foreground" />}
          loading={decisionsLoading}
        />
        <StatCard
          title="Alerts (7d)"
          value={alertsCount}
          description="Alerts in the last 7 days"
          icon={<Activity className="h-4 w-4 text-muted-foreground" />}
          loading={!alertsData && !decisionsLoading}
        />
        <StatCard
          title="Active Bouncers"
          value={bouncersCount}
          description="Connected enforcement agents"
          icon={<Users className="h-4 w-4 text-muted-foreground" />}
          loading={bouncersLoading}
        />
        <StatCard
          title="Containers"
          value={`${runningContainers}/${totalContainers}`}
          description={healthData?.allRunning ? 'All running' : 'Some containers down'}
          icon={<Container className="h-4 w-4 text-muted-foreground" />}
          loading={healthLoading}
        />
      </div>

      {/* Row 2: Decisions Over Time + Type Distribution */}
      <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
        <ChartCard title="Decisions Over Time" description="Recent decision activity">
          {decisionsOverTime.length > 0 ? (
            <AreaTimeline data={decisionsOverTime} height={280} />
          ) : (
            <div className="flex items-center justify-center h-[280px] text-muted-foreground text-sm">
              No decision data available
            </div>
          )}
        </ChartCard>
        <ChartCard title="Decision Types" description="Distribution by type">
          {decisionTypeData.length > 0 ? (
            <PieBreakdown data={decisionTypeData} height={280} />
          ) : (
            <div className="flex items-center justify-center h-[280px] text-muted-foreground text-sm">
              No decision data available
            </div>
          )}
        </ChartCard>
      </div>

      {/* Row 3: Top Blocked IPs */}
      {topBlockedIPs.length > 0 && (
        <ChartCard title="Top Blocked IPs" description="Most frequently targeted addresses">
          <BarDistribution data={topBlockedIPs} height={300} layout="horizontal" />
        </ChartCard>
      )}

      {/* Row 4: Container Status */}
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

      {healthData?.timestamp && (
        <p className="text-xs text-muted-foreground text-center">
          Last updated: {new Date(healthData.timestamp).toLocaleString()}
        </p>
      )}
    </div>
  )
}
