import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api, { Bouncer } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { Plus, Trash2, RefreshCw, Copy, Check, Shield, AlertCircle } from 'lucide-react'
import { toast } from 'sonner'

export default function Bouncers() {
  const queryClient = useQueryClient()
  const [newBouncerName, setNewBouncerName] = useState('')
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false)
  const [createdBouncer, setCreatedBouncer] = useState<{ name: string; api_key: string } | null>(null)
  const [copied, setCopied] = useState(false)

  const { data: bouncers, isLoading } = useQuery({
    queryKey: ['bouncers'],
    queryFn: async () => {
      const response = await api.crowdsec.getBouncers()
      // Handle both array and object response formats
      const data = response.data.data
      if (Array.isArray(data)) return data
      if (data && Array.isArray((data as any).bouncers)) return (data as any).bouncers
      return []
    },
  })

  const addBouncerMutation = useMutation({
    mutationFn: async (name: string) => {
      const response = await api.crowdsec.addBouncer(name)
      return response.data.data
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['bouncers'] })
      setCreatedBouncer(data)
      setNewBouncerName('')
      toast.success('Bouncer added successfully')
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to add bouncer')
    },
  })

  const deleteBouncerMutation = useMutation({
    mutationFn: async (name: string) => {
      await api.crowdsec.deleteBouncer(name)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['bouncers'] })
      toast.success('Bouncer deleted successfully')
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to delete bouncer')
    },
  })

  const handleAddBouncer = (e: React.FormEvent) => {
    e.preventDefault()
    if (!newBouncerName.trim()) return
    addBouncerMutation.mutate(newBouncerName)
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
    toast.success('API Key copied to clipboard')
  }

  const closeAddDialog = () => {
    setIsAddDialogOpen(false)
    setCreatedBouncer(null)
  }

  const getStatusBadge = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'connected':
        return <Badge className="bg-green-500">Connected</Badge>
      case 'disconnected':
        return <Badge variant="destructive">Disconnected</Badge>
      case 'stale':
        return <Badge className="bg-yellow-500">Stale</Badge>
      default:
        return <Badge variant="secondary">{status || 'Unknown'}</Badge>
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Bouncers</h1>
          <p className="text-muted-foreground mt-2">
            Manage CrowdSec enforcement agents
          </p>
        </div>
        <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Add Bouncer
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add New Bouncer</DialogTitle>
              <DialogDescription>
                Create a new bouncer API key. The key will be shown only once.
              </DialogDescription>
            </DialogHeader>

            {!createdBouncer ? (
              <form onSubmit={handleAddBouncer} className="space-y-4">
                <div className="space-y-2">
                  <label htmlFor="name" className="text-sm font-medium">
                    Bouncer Name
                  </label>
                  <Input
                    id="name"
                    placeholder="e.g., nginx-bouncer"
                    value={newBouncerName}
                    onChange={(e) => setNewBouncerName(e.target.value)}
                    disabled={addBouncerMutation.isPending}
                  />
                </div>
                <DialogFooter>
                  <Button type="submit" disabled={addBouncerMutation.isPending || !newBouncerName.trim()}>
                    {addBouncerMutation.isPending ? (
                      <>
                        <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                        Creating...
                      </>
                    ) : (
                      'Create Bouncer'
                    )}
                  </Button>
                </DialogFooter>
              </form>
            ) : (
              <div className="space-y-4">
                <div className="p-4 bg-muted rounded-lg space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-sm">API Key</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => copyToClipboard(createdBouncer.api_key)}
                    >
                      {copied ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                  <code className="block p-2 bg-background rounded border font-mono text-sm break-all">
                    {createdBouncer.api_key}
                  </code>
                  <p className="text-xs text-yellow-600 flex items-center gap-1">
                    <AlertCircle className="h-3 w-3" />
                    Copy this key now. It won't be shown again.
                  </p>
                </div>
                <DialogFooter>
                  <Button onClick={closeAddDialog}>Done</Button>
                </DialogFooter>
              </div>
            )}
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Registered Bouncers
          </CardTitle>
          <CardDescription>
            List of all bouncers registered with the Local API
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center p-8">
              <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : !bouncers || bouncers.length === 0 ? (
            <div className="text-center p-8 text-muted-foreground">
              No bouncers found. Add one to get started.
            </div>
          ) : (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Version</TableHead>
                    <TableHead>IP Address</TableHead>
                    <TableHead>Last Pull</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {bouncers.map((bouncer: Bouncer) => (
                    <TableRow key={bouncer.name}>
                      <TableCell className="font-medium">{bouncer.name}</TableCell>
                      <TableCell>{bouncer.type || '-'}</TableCell>
                      <TableCell>{bouncer.version || '-'}</TableCell>
                      <TableCell>{bouncer.ip_address || '-'}</TableCell>
                      <TableCell>
                        {bouncer.last_pull ? new Date(bouncer.last_pull).toLocaleString() : '-'}
                      </TableCell>
                      <TableCell>{getStatusBadge(bouncer.status || (bouncer.valid ? 'stale' : 'disconnected'))}</TableCell>
                      <TableCell className="text-right">
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button variant="ghost" size="icon" className="text-destructive hover:text-destructive hover:bg-destructive/10">
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>Delete Bouncer?</AlertDialogTitle>
                              <AlertDialogDescription>
                                Are you sure you want to delete <strong>{bouncer.name}</strong>?
                                This action cannot be undone and the bouncer will lose access immediately.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => deleteBouncerMutation.mutate(bouncer.name)}
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
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
