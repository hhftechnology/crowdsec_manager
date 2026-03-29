import { useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api, { Bouncer, AxiosErrorResponse } from '@/lib/api'
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
import { EmptyState, PageHeader, QueryError, ResultsSummary } from '@/components/common'
import { useUrlFilters } from '@/hooks'

/**
 * Type guard to check if an object is a valid Bouncer.
 * This provides runtime validation of the data received from the API.
 */
function isBouncer(obj: unknown): obj is Bouncer {
  return (
    obj !== null &&
    typeof obj === 'object' &&
    'name' in obj &&
    typeof (obj as { name: unknown }).name === 'string' &&
    'ip_address' in obj &&
    typeof (obj as { ip_address: unknown }).ip_address === 'string' &&
    'valid' in obj &&
    typeof (obj as { valid: unknown }).valid === 'boolean'
  )
}

function normalizeBouncers(raw: unknown): Bouncer[] {
  if (Array.isArray(raw)) {
    return raw.filter(isBouncer)
  }

  if (raw && typeof raw === 'object' && 'bouncers' in raw && Array.isArray((raw as { bouncers: unknown }).bouncers)) {
    return (raw as { bouncers: unknown[] }).bouncers.filter(isBouncer)
  }

  return []
}

export default function Bouncers() {
  const queryClient = useQueryClient()
  const [urlFilters, setUrlFilter] = useUrlFilters(['q'], { q: '' })
  const [newBouncerName, setNewBouncerName] = useState('')
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false)
  const [createdBouncer, setCreatedBouncer] = useState<{ name: string; api_key: string } | null>(null)
  const [copied, setCopied] = useState(false)

  const { data: bouncers, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['bouncers'],
    queryFn: async () => {
      const response = await api.crowdsec.getBouncers()
      return response.data.data
    },
    // The dashboard populates this cache key with the raw { bouncers, count }
    // payload shape, so normalize it per observer on the Bouncers page.
    select: normalizeBouncers,
  })

  const addBouncerMutation = useMutation({
    mutationFn: async (name: string) => {
      const response = await api.crowdsec.addBouncer(name)
      if (!response.data.data) {
        throw new Error('No data received from server')
      }
      return response.data.data
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['bouncers'] })
      setCreatedBouncer(data)
      setNewBouncerName('')
      toast.success('Bouncer added successfully')
    },
    onError: (error: AxiosErrorResponse) => {
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
    onError: (error: AxiosErrorResponse) => {
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
        return <Badge variant="success">Connected</Badge>
      case 'disconnected':
        return <Badge variant="destructive">Disconnected</Badge>
      case 'stale':
        return <Badge variant="warning">Stale</Badge>
      case 'pending':
        return <Badge variant="warning">Pending</Badge>
      case 'registered':
        return <Badge variant="outline">Registered</Badge>
      default:
        return <Badge variant="secondary">{status || 'Unknown'}</Badge>
    }
  }

  const filteredBouncers = useMemo(() => {
    if (!urlFilters.q) return bouncers ?? []
    const lower = (urlFilters.q as string).toLowerCase()
    return (bouncers ?? []).filter((bouncer: Bouncer) =>
      bouncer.name?.toLowerCase().includes(lower) ||
      bouncer.ip_address?.toLowerCase().includes(lower) ||
      bouncer.type?.toLowerCase().includes(lower)
    )
  }, [bouncers, urlFilters.q])

  return (
    <div className="space-y-6">
      <PageHeader
        title="Bouncers"
        description="Manage CrowdSec enforcement agents"
        breadcrumbs="Engines / Bouncers"
        actions={
          <div className="flex items-center gap-2">
            <Input
              placeholder="Search bouncers..."
              value={urlFilters.q as string}
              onChange={(event) => setUrlFilter('q', event.target.value)}
              className="h-9 w-56"
            />
            <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="h-4 w-4" />
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
                          <RefreshCw className="h-4 w-4 animate-spin" />
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
                          <Check className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                        ) : (
                          <Copy className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                    <code className="block p-2 bg-background rounded border font-mono text-sm break-all">
                      {createdBouncer.api_key}
                    </code>
                    <p className="text-xs text-amber-600 dark:text-amber-400 flex items-center gap-1">
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
        }
      />

      {isError && <QueryError error={error} onRetry={refetch} />}

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Registered Bouncers
            </CardTitle>
            <Badge variant="secondary">{bouncers?.length || 0}</Badge>
          </div>
          <CardDescription>
            List of all bouncers registered with the Local API
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center p-8">
              <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : !filteredBouncers || filteredBouncers.length === 0 ? (
            <EmptyState
              icon={Shield}
              title={urlFilters.q ? 'No bouncers matched your search' : 'No bouncers found'}
              description={urlFilters.q ? 'Try a different search term.' : 'Add a bouncer to get started.'}
            />
          ) : (
            <div className="rounded-md border">
              <div className="px-4 py-2">
                <ResultsSummary
                  total={bouncers?.length ?? 0}
                  filtered={filteredBouncers.length}
                  label="bouncers"
                  query={(urlFilters.q as string) || undefined}
                />
              </div>
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
                  {filteredBouncers.map((bouncer: Bouncer) => (
                    <TableRow key={bouncer.name}>
                      <TableCell className="font-medium">{bouncer.name}</TableCell>
                      <TableCell>{bouncer.type || '-'}</TableCell>
                      <TableCell>{bouncer.version || '-'}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <span>{bouncer.ip_address || '-'}</span>
                          {bouncer.ip_address && (
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => copyToClipboard(bouncer.ip_address)}
                            >
                              <Copy className="h-3.5 w-3.5" />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        {bouncer.last_pull ? new Date(bouncer.last_pull).toLocaleString() : '-'}
                      </TableCell>
                      <TableCell>{getStatusBadge(bouncer.status || (bouncer.valid ? 'stale' : 'disconnected'))}</TableCell>
                      <TableCell className="text-right">
                        <AlertDialog>
                          <AlertDialogTrigger className="inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-10 w-10 text-destructive hover:text-destructive hover:bg-destructive/10">
                            <Trash2 className="h-4 w-4" />
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
