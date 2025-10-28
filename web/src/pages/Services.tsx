import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tantml:react-query'
import { toast } from 'sonner'
import api, { ServiceActionRequest, EnrollRequest } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { CheckCircle2, XCircle, Play, Square, RotateCw, Power, Key } from 'lucide-react'

export default function Services() {
  const queryClient = useQueryClient()
  const [enrollmentKey, setEnrollmentKey] = useState('')
  const [isEnrollDialogOpen, setIsEnrollDialogOpen] = useState(false)

  const { data: servicesData, isLoading } = useQuery({
    queryKey: ['services'],
    queryFn: async () => {
      const response = await api.services.verify()
      return response.data.data || []
    },
    refetchInterval: 10000, // Refresh every 10 seconds
  })

  const actionMutation = useMutation({
    mutationFn: (data: ServiceActionRequest) => api.services.action(data),
    onSuccess: (_, variables) => {
      toast.success(`Service ${variables.action} command sent successfully`)
      queryClient.invalidateQueries({ queryKey: ['services'] })
    },
    onError: (_, variables) => {
      toast.error(`Failed to ${variables.action} service`)
    },
  })

  const shutdownMutation = useMutation({
    mutationFn: () => api.services.shutdown(),
    onSuccess: () => {
      toast.success('Graceful shutdown initiated')
      queryClient.invalidateQueries({ queryKey: ['services'] })
    },
    onError: () => {
      toast.error('Failed to initiate shutdown')
    },
  })

  const enrollMutation = useMutation({
    mutationFn: (data: EnrollRequest) => api.crowdsec.enroll(data),
    onSuccess: (response) => {
      toast.success('Enrollment completed successfully')
      setEnrollmentKey('')
      setIsEnrollDialogOpen(false)
      if (response.data.data?.output) {
        console.log('Enrollment output:', response.data.data.output)
      }
    },
    onError: () => {
      toast.error('Failed to enroll with CrowdSec')
    },
  })

  const handleAction = (service: string, action: 'start' | 'stop' | 'restart') => {
    actionMutation.mutate({ service, action })
  }

  const handleShutdown = () => {
    shutdownMutation.mutate()
  }

  const handleEnroll = (e: React.FormEvent) => {
    e.preventDefault()
    if (!enrollmentKey.trim()) {
      toast.error('Please enter an enrollment key')
      return
    }
    enrollMutation.mutate({ enrollment_key: enrollmentKey.trim() })
  }

  const getServiceStatus = (service: any): 'running' | 'stopped' | 'unknown' => {
    if (service.running === true) return 'running'
    if (service.running === false) return 'stopped'
    return 'unknown'
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Services Management</h1>
          <p className="text-muted-foreground mt-2">
            Control and monitor system services
          </p>
        </div>
        <Dialog open={isEnrollDialogOpen} onOpenChange={setIsEnrollDialogOpen}>
          <DialogTrigger asChild>
            <Button variant="outline">
              <Key className="mr-2 h-4 w-4" />
              Enroll CrowdSec
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Enroll with CrowdSec Console</DialogTitle>
              <DialogDescription>
                Connect your instance to CrowdSec Console for centralized management
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handleEnroll} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="enrollment-key">
                  Enrollment Key <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="enrollment-key"
                  type="text"
                  placeholder="Your CrowdSec Console enrollment key"
                  value={enrollmentKey}
                  onChange={(e) => setEnrollmentKey(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Get your enrollment key from the CrowdSec Console
                </p>
              </div>
              <Button
                type="submit"
                className="w-full"
                disabled={enrollMutation.isPending}
              >
                {enrollMutation.isPending ? 'Enrolling...' : 'Enroll Instance'}
              </Button>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Services Status Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {isLoading ? (
          <>
            <div className="h-48 bg-muted animate-pulse rounded-lg" />
            <div className="h-48 bg-muted animate-pulse rounded-lg" />
            <div className="h-48 bg-muted animate-pulse rounded-lg" />
          </>
        ) : servicesData && servicesData.length > 0 ? (
          servicesData.map((service: any, index: number) => {
            const status = getServiceStatus(service)
            return (
              <Card key={service.name || index}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg">
                      {service.name || 'Unknown Service'}
                    </CardTitle>
                    {status === 'running' ? (
                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                    ) : status === 'stopped' ? (
                      <XCircle className="h-5 w-5 text-red-500" />
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
                <Power className="mr-2 h-4 w-4" />
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
            <li>Alert notifications and monitoring</li>
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
