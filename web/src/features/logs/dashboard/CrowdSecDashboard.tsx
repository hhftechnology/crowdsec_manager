import { Activity, AlertTriangle, ShieldCheck, ShieldAlert } from 'lucide-react'
import { AreaTimeline, BarDistribution, ChartCard, PieBreakdown, StatCard, ThreatMap } from '@/components/charts'
import { Badge } from '@/components/ui/badge'
import type { CrowdSecDashboard as CrowdSecDashboardData } from '@/lib/api/dashboard'

interface CrowdSecDashboardProps {
  data: CrowdSecDashboardData | undefined
  isLoading?: boolean
}

function formatNumber(n: number): string {
  return n.toLocaleString()
}

export function CrowdSecDashboard({ data, isLoading }: CrowdSecDashboardProps) {
  const seriesData = (data?.series ?? []).map((b) => ({
    date: b.t.slice(11, 16),
    Alerts: b.alerts,
    Decisions: b.decisions,
    Errors: b.errors,
    value: b.alerts + b.decisions,
  }))

  const mapPoints = (data?.top_source_ips ?? [])
    .filter((ip) => typeof ip.lat === 'number' && typeof ip.lng === 'number')
    .map((ip) => ({
      lat: ip.lat as number,
      lng: ip.lng as number,
      value: ip.count,
      label: `${ip.ip}${ip.country ? ` (${ip.country})` : ''}`,
      country: ip.country,
    }))

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Events"
          value={isLoading ? '—' : formatNumber(data?.total_events ?? 0)}
          icon={<Activity className="h-4 w-4" />}
          loading={isLoading}
        />
        <StatCard
          title="Decisions"
          value={isLoading ? '—' : formatNumber(data?.decisions ?? 0)}
          icon={<ShieldCheck className="h-4 w-4" />}
          loading={isLoading}
        />
        <StatCard
          title="Alerts"
          value={isLoading ? '—' : formatNumber(data?.alerts ?? 0)}
          icon={<ShieldAlert className="h-4 w-4" />}
          loading={isLoading}
        />
        <StatCard
          title="Parser Errors"
          value={isLoading ? '—' : formatNumber(data?.parser_errors ?? 0)}
          icon={<AlertTriangle className="h-4 w-4" />}
          loading={isLoading}
        />
      </div>

      <ChartCard
        title="Event Volume"
        description="Alerts, decisions and parser errors over time"
        action={<Badge variant="outline">{data?.range ?? '—'}</Badge>}
      >
        {seriesData.length > 0 ? (
          <AreaTimeline data={seriesData} dataKey="value" xAxisKey="date" height={240} />
        ) : (
          <EmptyState message="No events in this window." />
        )}
      </ChartCard>

      <div className="grid gap-3 lg:grid-cols-2">
        <ChartCard title="Top Scenarios" description="Triggered detection rules">
          {data && data.top_scenarios.length > 0 ? (
            <BarDistribution data={data.top_scenarios} layout="horizontal" height={240} />
          ) : (
            <EmptyState message="No scenarios triggered." />
          )}
        </ChartCard>
        <ChartCard title="Decision Types">
          {data && data.top_decision_types.length > 0 ? (
            <PieBreakdown data={data.top_decision_types} height={240} />
          ) : (
            <EmptyState message="No decisions." />
          )}
        </ChartCard>
        <ChartCard title="Top Origins">
          {data && data.top_origins.length > 0 ? (
            <BarDistribution data={data.top_origins} height={240} />
          ) : (
            <EmptyState message="No origin data." />
          )}
        </ChartCard>
        <ChartCard title="Acquisition" description="Lines ingested per source">
          {data && data.acquisition.length > 0 ? (
            <BarDistribution
              data={data.acquisition.map((row) => ({ name: row.source, value: row.lines }))}
              layout="horizontal"
              height={240}
              color="hsl(var(--chart-2))"
            />
          ) : (
            <EmptyState message="No acquisition data — CrowdSec may be using a different log layout." />
          )}
        </ChartCard>
      </div>

      <ChartCard title="Top Offending IPs" description="Most frequent decision triggers">
        {mapPoints.length > 0 ? (
          <ThreatMap data={mapPoints} height={320} />
        ) : (
          <EmptyState message="No GeoIP data — install a GeoLite2-City database to populate the map." />
        )}
        <TopIPsTable rows={data?.top_source_ips ?? []} />
      </ChartCard>

      <div className="grid gap-3 lg:grid-cols-2">
        <ChartCard title="Bouncer Activity" description="Latest bouncer interactions">
          <ActivityFeed rows={data?.bouncer_activity ?? []} />
        </ChartCard>
        <ChartCard title="Recent Errors" description="Latest error log lines">
          <ActivityFeed rows={data?.recent_errors ?? []} highlightErrors />
        </ChartCard>
      </div>
    </div>
  )
}

function EmptyState({ message }: { message: string }) {
  return <div className="py-6 text-center text-sm text-muted-foreground">{message}</div>
}

function TopIPsTable({ rows }: { rows: CrowdSecDashboardData['top_source_ips'] }) {
  if (rows.length === 0) return null
  return (
    <div className="mt-3 overflow-hidden rounded-md border">
      <table className="w-full text-sm">
        <thead className="bg-muted text-xs uppercase text-muted-foreground">
          <tr>
            <th className="px-3 py-2 text-left">IP</th>
            <th className="px-3 py-2 text-left">Country</th>
            <th className="px-3 py-2 text-right">Triggers</th>
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 10).map((row) => (
            <tr key={row.ip} className="border-t">
              <td className="px-3 py-1.5 font-mono">{row.ip}</td>
              <td className="px-3 py-1.5">{row.country ?? '—'}</td>
              <td className="px-3 py-1.5 text-right">{row.count.toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ActivityFeed({
  rows,
  highlightErrors,
}: {
  rows: CrowdSecDashboardData['bouncer_activity']
  highlightErrors?: boolean
}) {
  if (rows.length === 0) {
    return <EmptyState message="Nothing to show." />
  }
  return (
    <ul className="divide-y rounded-md border">
      {rows.slice(0, 50).map((row, idx) => (
        <li key={`${row.t}-${idx}`} className="grid grid-cols-12 gap-2 px-3 py-2 text-sm">
          <span className="col-span-3 font-mono text-xs text-muted-foreground">{row.t.slice(11, 19)}</span>
          <span className="col-span-2">
            <Badge variant={highlightErrors && row.level === 'error' ? 'destructive' : 'secondary'}>
              {row.level}
            </Badge>
          </span>
          <span className="col-span-7 truncate text-muted-foreground">{row.message}</span>
        </li>
      ))}
    </ul>
  )
}
