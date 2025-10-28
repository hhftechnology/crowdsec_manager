import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { BackupRequest, RestoreRequest, Backup } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Database, Download, Trash2, RefreshCw, Plus, AlertTriangle } from 'lucide-react'

export default function Backup() {
  const queryClient = useQueryClient()
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [selectedBackup, setSelectedBackup] = useState<Backup | null>(null)

  const { data: backups, isLoading } = useQuery({
    queryKey: ['backups'],
    queryFn: async () => {
      const response = await api.backup.list()
      return response.data.data || []
    },
  })

  const createMutation = useMutation({
    mutationFn: (data: BackupRequest) => api.backup.create(data),
    onSuccess: () => {
      toast.success('Backup created successfully')
      setIsCreateDialogOpen(false)
      queryClient.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: () => {
      toast.error('Failed to create backup')
    },
  })

  const restoreMutation = useMutation({
    mutationFn: (data: RestoreRequest) => api.backup.restore(data),
    onSuccess: () => {
      toast.success('Backup restored successfully')
      setSelectedBackup(null)
      queryClient.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: () => {
      toast.error('Failed to restore backup')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.backup.delete(id),
    onSuccess: () => {
      toast.success('Backup deleted successfully')
      queryClient.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: () => {
      toast.error('Failed to delete backup')
    },
  })

  const cleanupMutation = useMutation({
    mutationFn: () => api.backup.cleanup(),
    onSuccess: () => {
      toast.success('Old backups cleaned up successfully')
      queryClient.invalidateQueries({ queryKey: ['backups'] })
    },
    onError: () => {
      toast.error('Failed to cleanup backups')
    },
  })

  const handleCreateBackup = () => {
    createMutation.mutate({
      dry_run: false,
    })
  }

  const handleRestore = (backup: Backup) => {
    restoreMutation.mutate({
      backup_id: backup.id,
      confirm: true,
    })
  }

  const handleDelete = (id: string) => {
    deleteMutation.mutate(id)
  }

  const handleCleanup = () => {
    cleanupMutation.mutate()
  }

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
  }

  const formatDate = (dateString: string): string => {
    return new Date(dateString).toLocaleString()
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Backup Management</h1>
          <p className="text-muted-foreground mt-2">
            Create, restore, and manage system backups
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={handleCleanup}
            disabled={cleanupMutation.isPending}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            Cleanup Old
          </Button>
          <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" />
                Create Backup
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create New Backup</DialogTitle>
                <DialogDescription>
                  Create a backup of all CrowdSec configurations and data
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div className="p-4 bg-muted rounded-lg space-y-2">
                  <p className="text-sm font-medium">Backup will include:</p>
                  <ul className="text-sm text-muted-foreground space-y-1 ml-4">
                    <li>" CrowdSec configurations</li>
                    <li>" Decision database</li>
                    <li>" Whitelists and parsers</li>
                    <li>" Custom scenarios</li>
                    <li>" Bouncer configurations</li>
                  </ul>
                </div>
                <Button
                  onClick={handleCreateBackup}
                  disabled={createMutation.isPending}
                  className="w-full"
                >
                  {createMutation.isPending ? 'Creating...' : 'Create Backup'}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Backups Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            Available Backups
          </CardTitle>
          <CardDescription>
            All created backups and their details
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-2">
              <div className="h-16 bg-muted animate-pulse rounded" />
              <div className="h-16 bg-muted animate-pulse rounded" />
              <div className="h-16 bg-muted animate-pulse rounded" />
            </div>
          ) : backups && backups.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Filename</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {backups.map((backup: Backup) => (
                  <TableRow key={backup.id}>
                    <TableCell className="font-mono text-sm">
                      {backup.filename}
                    </TableCell>
                    <TableCell className="text-sm">
                      {formatDate(backup.created_at)}
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">
                        {formatFileSize(backup.size)}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => setSelectedBackup(backup)}
                            >
                              <Download className="h-4 w-4" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle className="flex items-center gap-2">
                                <AlertTriangle className="h-5 w-5 text-orange-500" />
                                Restore Backup?
                              </AlertDialogTitle>
                              <AlertDialogDescription className="space-y-2">
                                <p>
                                  This will restore the system to the state saved in this backup.
                                </p>
                                <div className="p-3 bg-muted rounded-lg">
                                  <p className="text-sm font-mono">{backup.filename}</p>
                                  <p className="text-xs text-muted-foreground mt-1">
                                    Created: {formatDate(backup.created_at)}
                                  </p>
                                </div>
                                <p className="text-destructive font-medium">
                                  Warning: Current configurations will be overwritten!
                                </p>
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => handleRestore(backup)}
                                className="bg-orange-500 text-white hover:bg-orange-600"
                              >
                                Restore Backup
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>

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
                              <AlertDialogTitle>Delete Backup?</AlertDialogTitle>
                              <AlertDialogDescription>
                                This will permanently delete this backup file. This action cannot be undone.
                                <div className="mt-2 p-2 bg-muted rounded font-mono text-sm">
                                  {backup.filename}
                                </div>
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => handleDelete(backup.id)}
                                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                              >
                                Delete
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="text-center py-12">
              <Database className="mx-auto h-12 w-12 text-muted-foreground/50" />
              <p className="mt-4 text-muted-foreground">No backups available</p>
              <p className="text-sm text-muted-foreground mt-1">
                Click "Create Backup" to create your first backup
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Backup Information */}
      <Card>
        <CardHeader>
          <CardTitle>Backup Information</CardTitle>
          <CardDescription>
            Important information about backup and restore operations
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          <div className="flex items-start gap-2">
            <Database className="h-4 w-4 mt-0.5" />
            <div>
              <p className="font-medium text-foreground">Automatic Backups</p>
              <p>Backups are created automatically before critical operations like updates.</p>
            </div>
          </div>
          <div className="flex items-start gap-2">
            <RefreshCw className="h-4 w-4 mt-0.5" />
            <div>
              <p className="font-medium text-foreground">Restore Process</p>
              <p>Restoring a backup will overwrite current configurations. Services may be restarted.</p>
            </div>
          </div>
          <div className="flex items-start gap-2">
            <Trash2 className="h-4 w-4 mt-0.5" />
            <div>
              <p className="font-medium text-foreground">Cleanup</p>
              <p>The cleanup function removes backups older than 30 days to save disk space.</p>
            </div>
          </div>
          <div className="flex items-start gap-2">
            <AlertTriangle className="h-4 w-4 mt-0.5 text-orange-500" />
            <div>
              <p className="font-medium text-foreground">Best Practices</p>
              <p>Always create a backup before making significant configuration changes or updates.</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
