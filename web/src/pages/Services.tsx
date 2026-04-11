import { useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { ServiceActionRequest, ServiceInfo } from '@/lib/api'
import { ErrorContexts, getErrorMessage } from '@/lib/api/errors'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog'
import { CheckCircle2, XCircle, Play, Square, RotateCw, Power, Key } from 'lucide-react'
import EnrollDialog from '@/components/EnrollDialog'
import { PageHeader, QueryError } from '@/components/common'

export default function Services() {
  const queryClient = useQueryClient()

  const { data: servicesData, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['services'],
    queryFn: async () => {
      const response = await api.services.verify()
      return response.data.data || []
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  })

  const lastUpdatedLabel = useMemo(() => {
    if (!servicesData) return 'Not refreshed yet'
    return `Updated ${new Date().toLocaleTimeString()}`
  }, [servicesData])

  // Poll for enrollment status (keep this for the page-level awareness if needed, or remove if EnrollDialog handles it all)
  // Actually, the page doesn't use enrollmentData other than for the dialog.
  // So we can remove the polling here as EnrollDialog handles it.

  const actionMutation = useMutation({
    mutationFn: (data: ServiceActionRequest) => api.services.action(data),
    onSuccess: (_data: unknown, variables: ServiceActionRequest) => {
      toast.success(`Service ${variables.action} command sent successfully`)
      queryClient.invalidateQueries({ queryKey: ['services'] })
    },
    onError: (error: unknown, variables: ServiceActionRequest) => {
      const actionContext = {
        start: ErrorContexts.ServicesActionStart,
        stop: ErrorContexts.ServicesActionStop,
        restart: ErrorContexts.ServicesActionRestart,
      } as const
      toast.error(getErrorMessage(error, `Failed to ${variables.action} service`, actionContext[variables.action]))
    },
  })

  const shutdownMutation = useMutation({
    mutationFn: () => api.services.shutdown(),
    onSuccess: () => {
      toast.success('Graceful shutdown initiated')
      queryClient.invalidateQueries({ queryKey: ['services'] })
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, 'Failed to initiate shutdown', ErrorContexts.ServicesShutdown))
    },
  })

  const handleAction = (service: string, action: 'start' | 'stop' | 'restart') => {
    actionMutation.mutate({ service, action })
  }

  const handleShutdown = () => {
    shutdownMutation.mutate()
  }

  const getServiceStatus = (service: ServiceInfo): 'running' | 'stopped' | 'unknown' => {
    if (service.running === true) return 'running'
    if (service.running === false) return 'stopped'
    return 'unknown'
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Services Management"
        description="Control and monitor system services"
        actions={
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">{lastUpdatedLabel}</span>
            <EnrollDialog
              trigger={
                <Button variant="outline">
                  <Key className="h-4 w-4" />
                  Enroll CrowdSec
                </Button>
              }
            />
          </div>
        }
      />

      {isError && <QueryError error={error} onRetry={refetch} />}

      {/* Services Status Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {isLoading ? (
          <>
            <div className="h-48 bg-muted animate-pulse rounded-lg" />
            <div className="h-48 bg-muted animate-pulse rounded-lg" />
            <div className="h-48 bg-muted animate-pulse rounded-lg" />
          </>
        ) : servicesData && servicesData.length > 0 ? (
          servicesData.map((service: ServiceInfo, index: number) => {
            const status = getServiceStatus(service)
            return (
              <Card key={service.name || index}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg">
                      {service.name || 'Unknown Service'}
                    </CardTitle>
                    {status === 'running' ? (
                      <CheckCircle2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                    ) : status === 'stopped' ? (
                      <XCircle className="h-5 w-5 text-destructive" />
                    ) : (
                      <XCircle className="h-5 w-5 text-muted-foreground" />
                    )}
                  </div>
                  <CardDescription>
                    <Badge variant={status === 'running' ? 'default' : 'secondary'}>
                      {status}
                    </Badge>
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleAction(service.name, 'start')}
                      disabled={actionMutation.isPending || status === 'running'}
                      className="flex-1"
                    >
                      <Play className="mr-1 h-3 w-3" />
                      Start
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleAction(service.name, 'stop')}
                      disabled={actionMutation.isPending || status === 'stopped'}
                      className="flex-1"
                    >
                      <Square className="mr-1 h-3 w-3" />
                      Stop
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleAction(service.name, 'restart')}
                      disabled={actionMutation.isPending}
                      className="flex-1"
                    >
                      <RotateCw className="mr-1 h-3 w-3" />
                      Restart
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )
          })
        ) : (
          <Card className="col-span-full">
            <CardContent className="pt-6">
              <p className="text-center text-muted-foreground">
                No services found
              </p>
            </CardContent>
          </Card>
        )}
      </div>

      {/* System Actions */}
      <Card className="border-destructive">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <Power className="h-5 w-5" />
            System Actions
          </CardTitle>
          <CardDescription>
            Critical system-wide operations
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                variant="destructive"
                disabled={shutdownMutation.isPending}
              >
                <Power className="h-4 w-4" />
                Graceful Shutdown
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Initiate Graceful Shutdown?</AlertDialogTitle>
                <AlertDialogDescription>
                  This will gracefully stop all services and shut down the system.
                  All containers will be stopped in a controlled manner. This action
                  should only be performed when you intend to stop the entire stack.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  onClick={handleShutdown}
                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                >
                  Shutdown System
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </CardContent>
      </Card>

      {/* Enrollment Info */}
      <Card>
        <CardHeader>
          <CardTitle>CrowdSec Console Enrollment</CardTitle>
          <CardDescription>
            Connect your CrowdSec instance to the console for enhanced features
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <p className="text-sm text-muted-foreground">
            Enrolling with CrowdSec Console provides:
          </p>
          <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
            <li>Centralized management of multiple instances</li>
            <li>Access to CTI (Cyber Threat Intelligence)</li>
            <li>Real-time metrics and analytics</li>
            <li>Alert analysis and monitoring</li>
            <li>Community blocklists and scenarios</li>
          </ul>
          <div className="pt-2">
            <a
              href="https://app.crowdsec.net"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-primary hover:underline"
            >
              Get your enrollment key from CrowdSec Console →
            </a>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
