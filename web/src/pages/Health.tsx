import { useQuery } from '@tanstack/react-query'
import api from '@/lib/api'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { CheckCircle2, XCircle, Activity, Shield } from 'lucide-react'
import { StatusCard, CounterStatusCard } from '@/components/common/StatusCard'

export default function Health() {
  const { data: diagnostics, isLoading } = useQuery({
    queryKey: ['diagnostics'],
    queryFn: async () => {
      const response = await api.health.completeDiagnostics()
      return response.data.data
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  })

  const bouncers = diagnostics?.bouncers ?? []
  const allRunning = diagnostics?.health?.allRunning || false
  const runningContainers = diagnostics?.health?.containers?.filter(c => c.running).length || 0
  const totalContainers = diagnostics?.health?.containers?.length || 0

  return (
    <DashboardGrid
      title="Health & Diagnostics"
      description="Complete system diagnostics and health monitoring"
      loading={isLoading}
      lastUpdated={diagnostics?.timestamp ? new Date(diagnostics.timestamp) : undefined}
      alert={!isLoading && !allRunning ? {
        variant: 'destructive',
        title: 'System Issues Detected',
        description: 'Some containers are not running properly. Check the containers tab for details.'
      } : undefined}
      tabs={[
        {
          id: 'overview',
          label: 'Overview',
          layout: '2-col',
          sections: [
            {
              id: 'system-health',
              content: (
                <div className="grid gap-4 md:grid-cols-2">
                  <StatusCard
                    title="Containers"
                    value={`${runningContainers}/${totalContainers}`}
                    icon={Activity}
                    status={allRunning ? 'success' : 'error'}
                    description="Running containers"
                    loading={isLoading}
                  />
                  <CounterStatusCard
                    title="Active Bouncers"
                    count={bouncers.length}
                    icon={Shield}
                    description="Connected enforcement agents"
                    loading={isLoading}
                    threshold={{ warning: 1, error: 0 }}
                  />
                </div>
              )
            }
          ]
        },
        {
          id: 'containers',
          label: 'Containers',
          layout: '1-col',
          sections: [
            {
              id: 'container-status',
              title: 'Container Status',
              description: 'Status of all Docker containers in the stack',
              content: isLoading ? (
                <div className="space-y-2">
                  <div className="h-16 bg-muted animate-pulse rounded" />
                  <div className="h-16 bg-muted animate-pulse rounded" />
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Container ID</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Running</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {diagnostics?.health?.containers?.map((container) => (
                      <TableRow key={container.id}>
                        <TableCell className="font-medium">
                          {container.name}
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {container.id.substring(0, 12)}
                        </TableCell>
                        <TableCell>
                          <Badge variant={container.running ? 'default' : 'destructive'}>
                            {container.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {container.running ? (
                            <CheckCircle2 className="h-4 w-4 text-green-500" />
                          ) : (
                            <XCircle className="h-4 w-4 text-red-500" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )
            }
          ]
        },
        {
          id: 'bouncers',
          label: 'Bouncers',
          layout: '1-col',
          sections: [
            {
              id: 'bouncer-status',
              title: 'Connected Bouncers',
              description: 'Active enforcement agents connected to CrowdSec',
              content: isLoading ? (
                <div className="space-y-2">
                  <div className="h-16 bg-muted animate-pulse rounded" />
                  <div className="h-16 bg-muted animate-pulse rounded" />
                </div>
              ) : bouncers.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {bouncers.map((bouncer, index) => (
                      <TableRow key={index}>
                        <TableCell className="font-medium">
                          {bouncer.name}
                        </TableCell>
                        <TableCell>
                          <Badge>{bouncer.status}</Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <p className="text-muted-foreground text-center py-8">
                  No bouncers connected
                </p>
              )
            }
          ]
        },
        {
          id: 'traefik',
          label: 'Traefik Integration',
          layout: '1-col',
          sections: [
            {
              id: 'traefik-integration',
              title: 'Traefik Integration',
              description: 'Traefik middleware and configuration status',
              content: isLoading ? (
                <div className="space-y-2">
                  <div className="h-12 bg-muted animate-pulse rounded" />
                  <div className="h-12 bg-muted animate-pulse rounded" />
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-4 border rounded-lg">
                    <div>
                      <p className="font-medium">Middleware Configured</p>
                      <p className="text-sm text-muted-foreground">
                        CrowdSec middleware integration
                      </p>
                    </div>
                    {diagnostics?.traefik_integration?.middleware_configured ? (
                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                    ) : (
                      <XCircle className="h-5 w-5 text-red-500" />
                    )}
                  </div>

                  <div className="flex items-center justify-between p-4 border rounded-lg">
                    <div>
                      <p className="font-medium">LAPI Key Found</p>
                      <p className="text-sm text-muted-foreground">
                        Local API authentication key
                      </p>
                    </div>
                    {diagnostics?.traefik_integration?.lapi_key_found ? (
                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                    ) : (
                      <XCircle className="h-5 w-5 text-red-500" />
                    )}
                  </div>

                  <div className="flex items-center justify-between p-4 border rounded-lg">
                    <div>
                      <p className="font-medium">AppSec Enabled</p>
                      <p className="text-sm text-muted-foreground">
                        Application security features
                      </p>
                    </div>
                    {diagnostics?.traefik_integration?.appsec_enabled ? (
                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                    ) : (
                      <XCircle className="h-5 w-5 text-red-500" />
                    )}
                  </div>

                  {diagnostics?.traefik_integration?.config_files && diagnostics.traefik_integration.config_files.length > 0 && (
                    <div className="p-4 border rounded-lg">
                      <p className="font-medium mb-2">Configuration Files</p>
                      <ul className="space-y-1">
                        {diagnostics.traefik_integration.config_files.map((file, index) => (
                          <li key={index} className="text-sm font-mono text-muted-foreground">
                            {file}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )
            }
          ]
        }
      ]}
    />
  )
}
