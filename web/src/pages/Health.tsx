import { useQuery } from '@tanstack/react-query'
import api from '@/lib/api'
import { QueryError } from '@/components/common'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { CheckCircle2, XCircle, Activity, Shield, Globe } from 'lucide-react'

export default function Health() {
  const { data: diagnostics, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['diagnostics'],
    queryFn: async () => {
      const response = await api.health.completeDiagnostics()
      return response.data.data
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  })

  const bouncers = diagnostics?.bouncers ?? []
  const allRunning = diagnostics?.health?.allRunning || false

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Health & Diagnostics</h1>
        <p className="text-muted-foreground mt-2">
          Complete system diagnostics and health monitoring
        </p>
      </div>

      {isError && <QueryError error={error} onRetry={refetch} />}

      {/* System Status Overview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {isLoading ? (
              <Activity className="h-5 w-5 animate-pulse" />
            ) : allRunning ? (
              <CheckCircle2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
            ) : (
              <XCircle className="h-5 w-5 text-destructive" />
            )}
            System Status
          </CardTitle>
          <CardDescription>
            Overall health status: {allRunning ? 'Healthy' : 'Issues Detected'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-2">
              <div className="h-12 bg-muted animate-pulse rounded" />
              <div className="h-12 bg-muted animate-pulse rounded" />
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div>
                  <p className="text-sm font-medium">Containers</p>
                  <p className="text-2xl font-bold">
                    {diagnostics?.health?.containers?.filter(c => c.running).length || 0}
                    <span className="text-muted-foreground text-base">
                      /{diagnostics?.health?.containers?.length || 0}
                    </span>
                  </p>
                </div>
                <Badge variant={allRunning ? 'default' : 'destructive'}>
                  {allRunning ? 'Running' : 'Issues'}
                </Badge>
              </div>
              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div>
                  <p className="text-sm font-medium">Active Bouncers</p>
                  <p className="text-2xl font-bold">{bouncers.length}</p>
                </div>
                <Shield className="h-8 w-8 text-muted-foreground" />
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Detailed Diagnostics */}
      <Tabs defaultValue="containers" className="space-y-4">
        <TabsList>
          <TabsTrigger value="containers">Containers</TabsTrigger>
          <TabsTrigger value="bouncers">Bouncers</TabsTrigger>
          <TabsTrigger value="traefik">Traefik Integration</TabsTrigger>
        </TabsList>

        {/* Containers Tab */}
        <TabsContent value="containers">
          <Card>
            <CardHeader>
              <CardTitle>Container Status</CardTitle>
              <CardDescription>
                Status of all Docker containers in the stack
              </CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading ? (
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
                            <CheckCircle2 className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                          ) : (
                            <XCircle className="h-4 w-4 text-destructive" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Bouncers Tab */}
        <TabsContent value="bouncers">
          <Card>
            <CardHeader>
              <CardTitle>Connected Bouncers</CardTitle>
              <CardDescription>
                Active enforcement agents connected to CrowdSec
              </CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading ? (
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
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Traefik Integration Tab */}
        <TabsContent value="traefik">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe className="h-5 w-5" />
                Traefik Integration
              </CardTitle>
              <CardDescription>
                Traefik middleware and configuration status
              </CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading ? (
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
                      <CheckCircle2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <XCircle className="h-5 w-5 text-destructive" />
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
                      <CheckCircle2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <XCircle className="h-5 w-5 text-destructive" />
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
                      <CheckCircle2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <XCircle className="h-5 w-5 text-destructive" />
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
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Timestamp */}
      {diagnostics?.timestamp && (
        <p className="text-sm text-muted-foreground text-center">
          Last updated: {new Date(diagnostics.timestamp).toLocaleString()}
        </p>
      )}
    </div>
  )
}
