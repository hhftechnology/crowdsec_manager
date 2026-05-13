import { Activity, AlertTriangle, Clock, Users } from 'lucide-react'
import { AreaTimeline, BarDistribution, ChartCard, PieBreakdown, StatCard, ThreatMap } from '@/components/charts'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import type { TraefikDashboard as TraefikDashboardData } from '@/lib/api/dashboard'

interface TraefikDashboardProps {
  data: TraefikDashboardData | undefined
  isLoading?: boolean
}

function formatNumber(n: number): string {
  return n.toLocaleString()
}

function formatPercent(n: number): string {
  return `${(n * 100).toFixed(1)}%`
}

function formatDuration(ms: number | null | undefined): string {
  if (ms == null) return '—'
  if (ms < 1) return `${ms.toFixed(2)} ms`
  if (ms < 1000) return `${ms.toFixed(1)} ms`
  return `${(ms / 1000).toFixed(2)} s`
}

export function TraefikDashboard({ data, isLoading }: TraefikDashboardProps) {
  const totalRequests = data?.total_requests ?? 0
  const uniqueIPs = data?.unique_ips ?? 0
  const avgDuration = data?.avg_duration_ms ?? null
  const errorRate = data?.error_rate ?? 0
  const format = data?.format ?? 'clf'

  const seriesData = (data?.series ?? []).map((b) => ({
    date: b.t.slice(11, 16),
    Total: b.total,
    '2xx': b.c2xx,
    '3xx': b.c3xx,
    '4xx': b.c4xx,
    '5xx': b.c5xx,
    value: b.total,
  }))

  const mapPoints = (data?.top_ips ?? [])
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
          title="Total Requests"
          value={isLoading ? '—' : formatNumber(totalRequests)}
          icon={<Activity className="h-4 w-4" />}
          loading={isLoading}
        />
        <StatCard
          title="Unique IPs"
          value={isLoading ? '—' : formatNumber(uniqueIPs)}
          icon={<Users className="h-4 w-4" />}
          loading={isLoading}
        />
        <StatCard
          title="Avg Duration"
          value={isLoading ? '—' : formatDuration(avgDuration)}
          description={avgDuration == null ? 'Requires Traefik JSON access log' : undefined}
          icon={<Clock className="h-4 w-4" />}
          loading={isLoading}
        />
        <StatCard
          title="Error Rate"
          value={isLoading ? '—' : formatPercent(errorRate)}
          icon={<AlertTriangle className="h-4 w-4" />}
          loading={isLoading}
        />
      </div>

      <ChartCard
        title="Request Volume"
        description="Total requests bucketed by minute (or hour for 24h ranges)"
        action={<Badge variant="outline">{data?.range ?? '—'}</Badge>}
      >
        {seriesData.length > 0 ? (
          <AreaTimeline data={seriesData} dataKey="Total" xAxisKey="date" height={240} />
        ) : (
          <EmptyState message="No requests in the selected range." />
        )}
      </ChartCard>

      <div className="grid gap-3 lg:grid-cols-2">
        <ChartCard title="Status Codes" description="Distribution of HTTP response codes">
          {data?.status_codes && data.status_codes.length > 0 ? (
            <PieBreakdown data={data.status_codes} height={240} />
          ) : (
            <EmptyState message="No status codes recorded." />
          )}
        </ChartCard>
        <ChartCard title="HTTP Methods">
          {data?.methods && data.methods.length > 0 ? (
            <BarDistribution data={data.methods} height={240} />
          ) : (
            <EmptyState message="No method data." />
          )}
        </ChartCard>
      </div>

      <ChartCard title="Top Client IPs" description="By request count">
        {mapPoints.length > 0 ? (
          <ThreatMap data={mapPoints} height={320} />
        ) : (
          <EmptyState message="No GeoIP data — install a GeoLite2-City database to populate the map." />
        )}
        <TopIPsTable rows={data?.top_ips ?? []} />
      </ChartCard>

      {format === 'json' ? (
        <div className="grid gap-3 lg:grid-cols-2">
          <ChartCard title="Top Hosts">
            {data && data.top_hosts.length > 0 ? (
              <BarDistribution data={data.top_hosts} layout="horizontal" height={240} />
            ) : (
              <EmptyState message="No host data." />
            )}
          </ChartCard>
          <ChartCard title="Top Routers">
            {data && data.top_routers.length > 0 ? (
              <BarDistribution data={data.top_routers} layout="horizontal" height={240} />
            ) : (
              <EmptyState message="No router data." />
            )}
          </ChartCard>
          <ChartCard title="Slowest Endpoints" description="Max duration per path (ms)">
            {data && data.slowest_endpoints.length > 0 ? (
              <BarDistribution data={data.slowest_endpoints} layout="horizontal" height={240} color="hsl(var(--chart-3))" />
            ) : (
              <EmptyState message="No latency data." />
            )}
          </ChartCard>
          <ChartCard title="TLS Versions">
            {data && data.tls_versions.length > 0 ? (
              <PieBreakdown data={data.tls_versions} height={240} innerRadius={50} outerRadius={90} />
            ) : (
              <EmptyState message="No TLS data." />
            )}
          </ChartCard>
        </div>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Hosts, routers, latency &amp; TLS unavailable</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            Enable Traefik JSON access log (set <code className="rounded bg-muted px-1">accessLog.format = "json"</code>)
            to populate Top Hosts, Top Routers, Slowest Endpoints and TLS Versions widgets.
          </CardContent>
        </Card>
      )}

      <ChartCard title="Recent Errors" description="Latest 4xx and 5xx responses">
        <RecentErrorsFeed rows={data?.recent_errors ?? []} />
      </ChartCard>
    </div>
  )
}

function EmptyState({ message }: { message: string }) {
  return <div className="py-6 text-center text-sm text-muted-foreground">{message}</div>
}

function TopIPsTable({ rows }: { rows: TraefikDashboardData['top_ips'] }) {
  if (rows.length === 0) return null
  return (
    <div className="mt-3 overflow-hidden rounded-md border">
      <table className="w-full text-sm">
        <thead className="bg-muted text-xs uppercase text-muted-foreground">
          <tr>
            <th className="px-3 py-2 text-left">IP</th>
            <th className="px-3 py-2 text-left">Country</th>
            <th className="px-3 py-2 text-right">Requests</th>
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

function RecentErrorsFeed({ rows }: { rows: TraefikDashboardData['recent_errors'] }) {
  if (rows.length === 0) {
    return <EmptyState message="No errors in this window — nice!" />
  }
  return (
    <ul className="max-h-80 divide-y overflow-y-auto rounded-md border">
      {rows.slice(0, 50).map((row, idx) => (
        <li key={`${row.t}-${idx}`} className="grid grid-cols-12 gap-2 px-3 py-2 text-sm">
          <span className="col-span-3 font-mono text-xs text-muted-foreground">{row.t.slice(11, 19)}</span>
          <span className="col-span-2 font-mono">{row.ip}</span>
          <span className="col-span-1 font-mono">{row.method ?? '—'}</span>
          <span className="col-span-5 truncate font-mono text-muted-foreground">{row.path ?? '—'}</span>
          <span className="col-span-1 text-right">
            <Badge variant={row.status >= 500 ? 'destructive' : 'secondary'}>{row.status}</Badge>
          </span>
        </li>
      ))}
    </ul>
  )
}
