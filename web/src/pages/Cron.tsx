import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { CronJobRequest } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Clock, Plus, Trash2, AlertCircle } from 'lucide-react'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog'

export default function Cron() {
  const queryClient = useQueryClient()
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const [schedule, setSchedule] = useState('')
  const [task, setTask] = useState('')

  const { data: cronJobs, isLoading } = useQuery({
    queryKey: ['cron-jobs'],
    queryFn: async () => {
      const response = await api.cron.list()
      return response.data.data || []
    },
  })

  const setupMutation = useMutation({
    mutationFn: (data: CronJobRequest) => api.cron.setup(data),
    onSuccess: () => {
      toast.success('Cron job created successfully')
      setSchedule('')
      setTask('')
      setIsDialogOpen(false)
      queryClient.invalidateQueries({ queryKey: ['cron-jobs'] })
    },
    onError: () => {
      toast.error('Failed to create cron job')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.cron.delete(id),
    onSuccess: () => {
      toast.success('Cron job deleted successfully')
      queryClient.invalidateQueries({ queryKey: ['cron-jobs'] })
    },
    onError: () => {
      toast.error('Failed to delete cron job')
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (!schedule.trim()) {
      toast.error('Please enter a schedule')
      return
    }

    if (!task.trim()) {
      toast.error('Please enter a task')
      return
    }

    setupMutation.mutate({
      schedule: schedule.trim(),
      task: task.trim(),
    })
  }

  const handleDelete = (id: string) => {
    deleteMutation.mutate(id)
  }

  const cronExamples = [
    { schedule: '0 0 * * *', description: 'Daily at midnight' },
    { schedule: '0 */6 * * *', description: 'Every 6 hours' },
    { schedule: '*/15 * * * *', description: 'Every 15 minutes' },
    { schedule: '0 2 * * 0', description: 'Weekly on Sunday at 2 AM' },
    { schedule: '0 3 1 * *', description: 'Monthly on the 1st at 3 AM' },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Cron Job Management</h1>
          <p className="text-muted-foreground mt-2">
            Schedule and manage automated tasks
          </p>
        </div>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              New Cron Job
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Cron Job</DialogTitle>
              <DialogDescription>
                Schedule a new automated task using cron syntax
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="schedule">
                  Schedule (Cron Expression) <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="schedule"
                  type="text"
                  placeholder="0 0 * * *"
                  value={schedule}
                  onChange={(e) => setSchedule(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Format: minute hour day month weekday
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="task">
                  Task/Command <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="task"
                  type="text"
                  placeholder="/path/to/script.sh"
                  value={task}
                  onChange={(e) => setTask(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Command or script to execute
                </p>
              </div>

              <Button
                type="submit"
                className="w-full"
                disabled={setupMutation.isPending}
              >
                {setupMutation.isPending ? 'Creating...' : 'Create Cron Job'}
              </Button>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Cron Jobs Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Scheduled Jobs
          </CardTitle>
          <CardDescription>
            All configured cron jobs and their schedules
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-2">
              <div className="h-16 bg-muted animate-pulse rounded" />
              <div className="h-16 bg-muted animate-pulse rounded" />
            </div>
          ) : cronJobs && cronJobs.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Schedule</TableHead>
                  <TableHead>Task</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {cronJobs.map((job: any, index: number) => (
                  <TableRow key={job.id || index}>
                    <TableCell className="font-mono text-sm">
                      {job.schedule}
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {job.task}
                    </TableCell>
                    <TableCell>
                      <Badge variant={job.enabled ? 'default' : 'secondary'}>
                        {job.enabled ? 'Active' : 'Inactive'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={deleteMutation.isPending}
                          >
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Delete Cron Job?</AlertDialogTitle>
                            <AlertDialogDescription>
                              This will permanently delete this cron job. This action cannot be undone.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              onClick={() => handleDelete(job.id || String(index))}
                              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                            >
                              Delete
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="text-center py-8">
              <Clock className="mx-auto h-12 w-12 text-muted-foreground/50" />
              <p className="mt-4 text-muted-foreground">No cron jobs configured</p>
              <p className="text-sm text-muted-foreground mt-1">
                Click "New Cron Job" to create your first scheduled task
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Cron Syntax Reference */}
      <Card>
        <CardHeader>
          <CardTitle>Cron Syntax Reference</CardTitle>
          <CardDescription>
            Common cron schedule patterns
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Schedule</TableHead>
                <TableHead>Description</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {cronExamples.map((example, index) => (
                <TableRow key={index}>
                  <TableCell className="font-mono text-sm">
                    {example.schedule}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {example.description}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <div className="mt-4 p-4 bg-muted rounded-lg">
            <div className="flex items-start gap-2">
              <AlertCircle className="h-4 w-4 mt-0.5 text-muted-foreground" />
              <div className="text-sm text-muted-foreground">
                <p className="font-medium mb-1">Cron Format:</p>
                <p className="font-mono">* * * * *</p>
                <p className="mt-1">minute (0-59) | hour (0-23) | day (1-31) | month (1-12) | weekday (0-6)</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
