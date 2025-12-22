import { useQuery } from '@tanstack/react-query'
import api from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { AlertCircle, CheckCircle2, Container, Shield, Users } from 'lucide-react'
import { StandardizedStatusCard as StatusCard, CounterStatusCard } from '@/components/common/StandardizedStatusCard'
import { ResponsiveGrid } from '@/components/ui/responsive-grid'
import { useBreakpoints } from '@/hooks/useMediaQuery'
import { cn } from '@/lib/utils'

export default function Dashboard() {
  const { isMobile, needsTouchOptimization } = useBreakpoints()
  
  const { data: healthData, isLoading: healthLoading, error: healthError } = useQuery({
    queryKey: ['health'],
    queryFn: async () => {
      const response = await api.health.checkStack()
      return response.data.data
    },
    refetchInterval: 5000, // Refresh every 5 seconds
    retry: 1, // Only retry once
  })

  const { data: decisionsData, isLoading: decisionsLoading, error: decisionsError } = useQuery({
    queryKey: ['decisions'],
    queryFn: async () => {
      const response = await api.crowdsec.getDecisions()
      return response.data.data
    },
    refetchInterval: 10000, // Refresh every 10 seconds
    retry: 1, // Only retry once
  })

  const { data: bouncersData, isLoading: bouncersLoading, error: bouncersError } = useQuery({
    queryKey: ['bouncers'],
    queryFn: async () => {
      const response = await api.crowdsec.getBouncers()
      return response.data.data
    },
    refetchInterval: 30000, // Refresh every 30 seconds
    retry: 1, // Only retry once
  })

  // Check if we have connection errors
  const hasConnectionError = healthError || decisionsError || bouncersError

  const parseDecisionsCount = (data: any): number => {
    if (!data) return 0
    // If the API returns a count field, use it (preferred)
    if (typeof data.count === 'number') return data.count
    // If decisions array is available, use its length
    if (Array.isArray(data.decisions)) return data.decisions.length
    // Fallback to parsing the string (legacy support)
    if (typeof data.decisions === 'string') {
      const lines = data.decisions.split('\n').filter((line: string) => line.trim())
      return Math.max(0, lines.length - 2)
    }
    return 0
  }

  const parseBouncersCount = (data: any): number => {
    if (!data) return 0
    if (typeof data.count === 'number') return data.count
    if (Array.isArray(data)) return data.length
    if (data.bouncers && Array.isArray(data.bouncers)) return data.bouncers.length
    return 0
  }

  const decisionsCount = parseDecisionsCount(decisionsData)
  const bouncersCount = parseBouncersCount(bouncersData)

  return (
    <div className="space-y-6">
      <div>
        <h1 className={cn(
          "font-bold",
          isMobile ? "text-2xl" : "text-3xl"
        )}>
          Dashboard
        </h1>
        <p className="text-muted-foreground mt-2">
          System overview and health status
        </p>
      </div>

      {/* Connection Error Banner */}
      {hasConnectionError && (
        <Card className="border-destructive bg-destructive/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-destructive">
              <AlertCircle className="h-5 w-5" />
              Backend Connection Error
            </CardTitle>
            <CardDescription>
              Unable to connect to the CrowdSec Manager backend server. Please ensure:
              <ul className="list-disc list-inside mt-2 space-y-1">
                <li>The backend server is running on port 8080</li>
                <li>Docker containers are properly configured</li>
                <li>Network connectivity is available</li>
              </ul>
            </CardDescription>
          </CardHeader>
        </Card>
      )}

      {/* System Health Status */}
      <Card className={cn(
        "transition-all duration-200",
        needsTouchOptimization && "active:scale-[0.98]"
      )}>
        <CardHeader>
          <CardTitle className={cn(
            "flex items-center gap-2",
            isMobile ? "text-lg" : "text-xl"
          )}>
            {healthLoading ? (
              <AlertCircle className="h-5 w-5 animate-pulse" />
            ) : healthData?.allRunning ? (
              <CheckCircle2 className="h-5 w-5 text-green-500" />
            ) : (
              <AlertCircle className="h-5 w-5 text-red-500" />
            )}
            System Health
          </CardTitle>
          <CardDescription>
            {healthData?.allRunning
              ? 'All containers are running'
              : 'Some containers are not running'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {healthData?.containers.map((container: any) => (
              <div
                key={container.id}
                className={cn(
                  "flex items-center justify-between rounded-lg border transition-colors",
                  isMobile ? "p-3" : "p-3",
                  needsTouchOptimization && "min-h-[44px] active:bg-accent/50"
                )}
              >
                <div className="flex items-center gap-3 min-w-0 flex-1">
                  <Container className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                  <div className="min-w-0 flex-1">
                    <p className={cn(
                      "font-medium truncate",
                      isMobile ? "text-sm" : "text-base"
                    )}>
                      {container.name}
                    </p>
                    <p className={cn(
                      "text-muted-foreground truncate",
                      isMobile ? "text-xs" : "text-sm"
                    )}>
                      {container.id.substring(0, 12)}
                    </p>
                  </div>
                </div>
                <Badge
                  variant={container.running ? 'default' : 'destructive'}
                  className={isMobile ? "text-xs" : ""}
                >
                  {container.status}
                </Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Statistics Grid */}
      <ResponsiveGrid
        cols={{ mobile: 1, tablet: 2, desktop: 3 }}
        gap={isMobile ? "sm" : "md"}
      >
        {/* Active Decisions */}
        <CounterStatusCard
          title="Active Decisions"
          count={decisionsLoading ? 0 : decisionsCount}
          icon={Shield}
          description="IPs currently blocked"
          loading={decisionsLoading}
          threshold={{ warning: 50, error: 100 }}
        />

        {/* Active Bouncers */}
        <CounterStatusCard
          title="Active Bouncers"
          count={bouncersLoading ? 0 : bouncersCount}
          icon={Users}
          description="Connected enforcement agents"
          loading={bouncersLoading}
          threshold={{ warning: 1, error: 0 }}
        />

        {/* Containers Status */}
        <StatusCard
          title="Containers"
          value={healthLoading ? "Loading..." : `${healthData?.containers.filter((c: any) => c.running).length || 0}/${healthData?.containers.length || 0}`}
          icon={Container}
          status={healthLoading ? 'neutral' : healthData?.allRunning ? 'success' : 'error'}
          description="Running containers"
          loading={healthLoading}
        />
      </ResponsiveGrid>

      {/* Timestamp */}
      {healthData?.timestamp && (
        <p className={cn(
          "text-muted-foreground text-center",
          isMobile ? "text-xs" : "text-sm"
        )}>
          Last updated: {new Date(healthData.timestamp).toLocaleString()}
        </p>
      )}
    </div>
  )
}