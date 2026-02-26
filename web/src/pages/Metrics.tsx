import { useQuery } from '@tanstack/react-query'
import { crowdsecAPI } from '@/lib/api/crowdsec'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { RefreshCw, BarChart3 } from 'lucide-react'
import { PageHeader, PageLoader, QueryError } from '@/components/common'

export default function Metrics() {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['crowdsec-metrics'],
    queryFn: async () => {
      const response = await crowdsecAPI.getMetrics()
      return response.data.data as { metrics: string }
    },
    refetchInterval: 30000,
  })

  return (
    <div className="space-y-6">
      <PageHeader
        title="CrowdSec Metrics"
        description="Real-time metrics from the CrowdSec engine"
      />

      {isError && <QueryError error={error} onRetry={refetch} />}

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5" />
              <div>
                <CardTitle>Engine Metrics</CardTitle>
                <CardDescription>
                  CrowdSec LAPI metrics output
                </CardDescription>
              </div>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetch()}
              disabled={isLoading}
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <PageLoader message="Loading metrics..." />
          ) : data?.metrics ? (
            <pre className="p-4 bg-muted rounded-lg text-sm overflow-auto whitespace-pre-wrap font-mono max-h-[70vh]">
              {data.metrics}
            </pre>
          ) : (
            <p className="text-muted-foreground text-sm">No metrics data available</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
