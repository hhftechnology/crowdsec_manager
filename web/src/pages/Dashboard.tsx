import { useQuery } from '@tanstack/react-query'
import api from '@/lib/api'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { AlertCircle, Container, Shield, Users } from 'lucide-react'
import { StandardizedStatusCard as StatusCard, CounterStatusCard } from '@/components/common/StandardizedStatusCard'
import { ResponsiveGrid } from '@/components/ui/responsive-grid'
import { useBreakpoints } from '@/hooks/useMediaQuery'
import { cn } from '@/lib/utils'
import { useDeployment, useContainers } from '@/contexts/DeploymentContext'
import { ContainerStatusList } from '@/components/dashboard/ContainerStatusList'

export default function Dashboard() {
  const { isMobile } = useBreakpoints()
  
  /* Deployment Context Integration */
  const { deployment, isLoading: deploymentLoading, error: deploymentError } = useDeployment()
  const containers = useContainers()
  
  // Calculate health stats from context
  const runningContainers = containers.filter(c => c.running)
  const allRunning = containers.length > 0 && containers.every(c => c.running)

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
  // Check if we have connection errors
  const hasConnectionError = !!deploymentError || !!decisionsError || !!bouncersError

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
    
    // Try to get the list of bouncers to filter by status
    let bouncersList: any[] = []
    if (Array.isArray(data)) {
      bouncersList = data
    } else if (data.bouncers && Array.isArray(data.bouncers)) {
      bouncersList = data.bouncers
    }
    
    // If we have a list, count only connected bouncers
    if (bouncersList.length > 0) {
      return bouncersList.filter((b: any) => b?.status?.toLowerCase() === 'connected').length
    }
    
    // Fallback to count property if list is not available (though it should be)
    if (typeof data.count === 'number') return data.count
    
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

      {/* System Health Status - Grouped by Role */}
      <ContainerStatusList containers={containers} isLoading={deploymentLoading} />

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
          threshold={{ error: 0 }}
          higherIsBetter={true}
        />

        {/* Containers Status */}
        {/* Containers Status */}
        <StatusCard
          title="Containers"
          value={deploymentLoading ? "Loading..." : `${runningContainers.length}/${containers.length}`}
          icon={Container}
          variant={deploymentLoading ? 'neutral' : allRunning ? 'success' : 'error'}
          description="Running containers"
          loading={deploymentLoading}
        />
      </ResponsiveGrid>

      {/* Timestamp */}
      {deployment?.detectedAt && (
        <p className={cn(
          "text-muted-foreground text-center",
          isMobile ? "text-xs" : "text-sm"
        )}>
          Last updated: {new Date(deployment.detectedAt).toLocaleString()}
        </p>
      )}
    </div>
  )
}