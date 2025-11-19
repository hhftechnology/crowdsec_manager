import { useQuery } from '@tanstack/react-query'
import api from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { AlertCircle, CheckCircle2, Container, Shield, Users } from 'lucide-react'

export default function Dashboard() {
  const { data: healthData, isLoading: healthLoading } = useQuery({
    queryKey: ['health'],
    queryFn: async () => {
      const response = await api.health.checkStack()
      return response.data.data
    },
    refetchInterval: 5000, // Refresh every 5 seconds
  })

  const { data: decisionsData, isLoading: decisionsLoading } = useQuery({
    queryKey: ['decisions'],
    queryFn: async () => {
      const response = await api.crowdsec.getDecisions()
      return response.data.data
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  })

  const { data: bouncersData, isLoading: bouncersLoading } = useQuery({
    queryKey: ['bouncers'],
    queryFn: async () => {
      const response = await api.crowdsec.getBouncers()
      return response.data.data
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  // FIXED: Properly handle the structured JSON response from the API
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
    // If the API returns a count field, use it
    if (typeof data.count === 'number') return data.count
    // If bouncers array is available, use its length
    if (Array.isArray(data.bouncers)) return data.bouncers.length
    // Fallback to parsing the string
    if (typeof data.bouncers === 'string') {
      const lines = data.bouncers.split('\n').filter((line: string) => line.trim())
      return Math.max(0, lines.length - 2)
    }
    return 0
  }

  const decisionsCount = parseDecisionsCount(decisionsData)
  const bouncersCount = parseBouncersCount(bouncersData)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground mt-2">
          System overview and health status
        </p>
      </div>

      {/* System Health Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
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
            {healthData?.containers.map((container) => (
              <div
                key={container.id}
                className="flex items-center justify-between p-3 rounded-lg border"
              >
                <div className="flex items-center gap-3">
                  <Container className="h-4 w-4 text-muted-foreground" />
                  <div>
                    <p className="font-medium">{container.name}</p>
                    <p className="text-sm text-muted-foreground">
                      {container.id.substring(0, 12)}
                    </p>
                  </div>
                </div>
                <Badge
                  variant={container.running ? 'default' : 'destructive'}
                >
                  {container.status}
                </Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Statistics Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {/* Active Decisions */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Active Decisions
            </CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {decisionsLoading ? (
                <div className="h-8 w-16 animate-pulse bg-muted rounded" />
              ) : (
                decisionsCount
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              IPs currently blocked
            </p>
          </CardContent>
        </Card>

        {/* Active Bouncers */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Active Bouncers
            </CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {bouncersLoading ? (
                <div className="h-8 w-16 animate-pulse bg-muted rounded" />
              ) : (
                bouncersCount
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Connected enforcement agents
            </p>
          </CardContent>
        </Card>

        {/* Containers Status */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Containers
            </CardTitle>
            <Container className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {healthLoading ? (
                <div className="h-8 w-16 animate-pulse bg-muted rounded" />
              ) : (
                <>
                  {healthData?.containers.filter(c => c.running).length || 0}
                  <span className="text-muted-foreground text-base">
                    /{healthData?.containers.length || 0}
                  </span>
                </>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Running containers
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Timestamp */}
      {healthData?.timestamp && (
        <p className="text-sm text-muted-foreground text-center">
          Last updated: {new Date(healthData.timestamp).toLocaleString()}
        </p>
      )}
    </div>
  )
}