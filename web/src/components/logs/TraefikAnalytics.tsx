import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { BarChart3, RefreshCw } from 'lucide-react'

interface TraefikStats {
  total_lines?: number
  top_ips?: { ip: string; count: number }[]
  error_entries?: unknown[]
  status_codes?: Record<string, number>
  http_methods?: Record<string, number>
}

interface TraefikAnalyticsProps {
  stats: TraefikStats | undefined
  isLoading: boolean
  onRefresh: () => void
}

function TraefikAnalytics({ stats, isLoading, onRefresh }: TraefikAnalyticsProps) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5" />
              Advanced Analytics
            </CardTitle>
            <CardDescription>
              Traffic analysis from Traefik access logs
            </CardDescription>
          </div>
          <Button
            onClick={onRefresh}
            disabled={isLoading}
            size="sm"
            variant="outline"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            <div className="h-24 bg-muted animate-pulse rounded" />
            <div className="h-24 bg-muted animate-pulse rounded" />
          </div>
        ) : stats ? (
          <div className="space-y-6">
            {/* Summary */}
            <div className="grid gap-4 md:grid-cols-3">
              <div className="p-4 border rounded-lg">
                <p className="text-sm text-muted-foreground">Total Requests</p>
                <p className="text-2xl font-bold">{stats.total_lines || 0}</p>
              </div>
              <div className="p-4 border rounded-lg">
                <p className="text-sm text-muted-foreground">Unique IPs</p>
                <p className="text-2xl font-bold">{stats.top_ips?.length || 0}</p>
              </div>
              <div className="p-4 border rounded-lg">
                <p className="text-sm text-muted-foreground">Error Entries</p>
                <p className="text-2xl font-bold">{stats.error_entries?.length || 0}</p>
              </div>
            </div>

            {/* Top IPs */}
            {stats.top_ips && stats.top_ips.length > 0 && (
              <div>
                <h3 className="font-semibold mb-2">Top IP Addresses</h3>
                <div className="space-y-2">
                  {stats.top_ips.slice(0, 10).map((ipData, index) => (
                    <div key={index} className="flex items-center justify-between p-2 border rounded">
                      <span className="font-mono text-sm">{ipData.ip}</span>
                      <Badge>{ipData.count} requests</Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Status Codes */}
            {stats.status_codes && Object.keys(stats.status_codes).length > 0 && (
              <div>
                <h3 className="font-semibold mb-2">HTTP Status Codes</h3>
                <div className="grid gap-2 md:grid-cols-3">
                  {Object.entries(stats.status_codes).map(([code, count]) => (
                    <div key={code} className="flex items-center justify-between p-2 border rounded">
                      <span className="font-mono text-sm">{code}</span>
                      <Badge variant={code.startsWith('2') ? 'default' : code.startsWith('4') ? 'secondary' : 'destructive'}>
                        {String(count)}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* HTTP Methods */}
            {stats.http_methods && Object.keys(stats.http_methods).length > 0 && (
              <div>
                <h3 className="font-semibold mb-2">HTTP Methods</h3>
                <div className="grid gap-2 md:grid-cols-4">
                  {Object.entries(stats.http_methods).map(([method, count]) => (
                    <div key={method} className="flex items-center justify-between p-2 border rounded">
                      <span className="font-mono text-sm">{method}</span>
                      <Badge>{String(count)}</Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <p className="text-center text-muted-foreground py-8">
            No analytics data available
          </p>
        )}
      </CardContent>
    </Card>
  )
}

export { TraefikAnalytics }
export type { TraefikAnalyticsProps, TraefikStats }
