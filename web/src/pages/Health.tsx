import { useQuery } from '@tanstack/react-query'
import api from '@/lib/api'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { CheckCircle2, XCircle, Activity, Shield } from 'lucide-react'
import { StandardizedStatusCard as StatusCard, CounterStatusCard } from '@/components/common/StandardizedStatusCard'
import { DashboardGrid } from '@/components/common/DashboardGrid'
import { useDeployment, useRunningContainers, useContainers, useProxyType } from '@/contexts/DeploymentContext'

export default function Health() {
  const { isLoading: deploymentLoading } = useDeployment()
  const runningContainers = useRunningContainers()
  const allContainers = useContainers()
  const proxyType = useProxyType()

  const { data: diagnostics, isLoading } = useQuery({
    queryKey: ['diagnostics'],
    queryFn: async () => {
      const response = await api.health.completeDiagnostics()
      return response.data.data
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  })

  // Filter containers to only show those in current deployment
  const deploymentContainers = allContainers
  const runningDeploymentContainers = runningContainers

  const bouncers = diagnostics?.bouncers ?? []
  const allRunning = runningDeploymentContainers.length === deploymentContainers.length && deploymentContainers.length > 0
  const runningContainerCount = runningDeploymentContainers.length
  const totalContainerCount = deploymentContainers.length

  // Group containers by role for better organization
  const containersByRole = deploymentContainers.reduce((acc, container) => {
    if (!acc[container.role]) {
      acc[container.role] = []
    }
    acc[container.role].push(container)
    return acc
  }, {} as Record<string, typeof deploymentContainers>)

  // Check if Traefik integration should be shown
  const hasTraefikContainer = runningDeploymentContainers.some(c => 
    c.name.toLowerCase().includes('traefik') && c.running
  )
  const shouldShowTraefikIntegration = hasTraefikContainer || proxyType === 'traefik'

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
                    value={`${runningContainerCount}/${totalContainerCount}`}
                    icon={Activity}
                    variant={allRunning ? 'success' : 'error'}
                    description="Running containers in deployment"
                    loading={isLoading || deploymentLoading}
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
              description: 'Status of containers in current deployment',
              content: isLoading || deploymentLoading ? (
                <div className="space-y-2">
                  <div className="h-16 bg-muted animate-pulse rounded" />
                  <div className="h-16 bg-muted animate-pulse rounded" />
                </div>
              ) : deploymentContainers.length > 0 ? (
                <div className="space-y-4">
                  {/* Group containers by role */}
                  {Object.entries(containersByRole).map(([role, containers]) => (
                    containers.length > 0 && (
                      <div key={role} className="space-y-2">
                        <h4 className="text-sm font-medium text-muted-foreground capitalize">
                          {role} Containers
                        </h4>
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Name</TableHead>
                              <TableHead>Container ID</TableHead>
                              <TableHead>Status</TableHead>
                              <TableHead>Running</TableHead>
                              <TableHead>Capabilities</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {containers.map((container) => (
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
                                <TableCell>
                                  <div className="flex flex-wrap gap-1">
                                    {container.capabilities.map((capability) => (
                                      <Badge key={capability} variant="outline" className="text-xs">
                                        {capability}
                                      </Badge>
                                    ))}
                                  </div>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                    )
                  ))}
                </div>
              ) : (
                <p className="text-muted-foreground text-center py-8">
                  No containers detected in current deployment
                </p>
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
        // Only show Traefik integration tab if Traefik is present in deployment
        ...(shouldShowTraefikIntegration ? [{
          id: 'traefik',
          label: 'Traefik Integration',
          layout: '1-col' as const,
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
        }] : [])
      ]}
    />
  )
}
