import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { Allowlist as AllowlistType, AllowlistCreateRequest, AllowlistAddEntriesRequest, AllowlistRemoveEntriesRequest, AxiosErrorResponse } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { Plus, Trash2, Eye, RefreshCw, Info, ListChecks } from 'lucide-react'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { PageHeader, EmptyState, QueryError, ResultsSummary } from '@/components/common'
import { InspectDialog } from '@/components/allowlist/InspectDialog'
import { ManageEntries } from '@/components/allowlist/ManageEntries'

export default function Allowlist() {
  const queryClient = useQueryClient()
  const [newAllowlistName, setNewAllowlistName] = useState('')
  const [newAllowlistDescription, setNewAllowlistDescription] = useState('')
  const [selectedAllowlist, setSelectedAllowlist] = useState<string>('')
  const [inspectDialogOpen, setInspectDialogOpen] = useState(false)
  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [showNoAllowlistOption, setShowNoAllowlistOption] = useState(true)

  const { data: allowlistsData, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['allowlists'],
    queryFn: async () => {
      const response = await api.allowlist.list()
      if (Array.isArray(response.data.data)) {
        return response.data.data
      }
      return response.data.data?.allowlists || []
    },
  })

  const { data: inspectData, isLoading: isInspecting } = useQuery({
    queryKey: ['allowlist-inspect', selectedAllowlist],
    queryFn: async () => {
      if (!selectedAllowlist) return null
      const response = await api.allowlist.inspect(selectedAllowlist)
      return response.data.data
    },
    enabled: !!selectedAllowlist && inspectDialogOpen,
  })

  const createMutation = useMutation({
    mutationFn: (data: AllowlistCreateRequest) => api.allowlist.create(data),
    onSuccess: () => {
      toast.success('Allowlist created successfully')
      setNewAllowlistName('')
      setNewAllowlistDescription('')
      setCreateDialogOpen(false)
      queryClient.invalidateQueries({ queryKey: ['allowlists'] })
    },
    onError: (error: AxiosErrorResponse) => {
      toast.error(error.response?.data?.error || 'Failed to create allowlist')
    },
  })

  const addEntriesMutation = useMutation({
    mutationFn: (data: AllowlistAddEntriesRequest) => api.allowlist.addEntries(data),
    onSuccess: () => {
      toast.success('Entries added successfully')
      queryClient.invalidateQueries({ queryKey: ['allowlist-inspect'] })
    },
    onError: (error: AxiosErrorResponse) => {
      toast.error(error.response?.data?.error || 'Failed to add entries')
    },
  })

  const removeEntriesMutation = useMutation({
    mutationFn: (data: AllowlistRemoveEntriesRequest) => api.allowlist.removeEntries(data),
    onSuccess: () => {
      toast.success('Entries removed successfully')
      queryClient.invalidateQueries({ queryKey: ['allowlist-inspect'] })
    },
    onError: (error: AxiosErrorResponse) => {
      toast.error(error.response?.data?.error || 'Failed to remove entries')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (name: string) => api.allowlist.delete(name),
    onSuccess: () => {
      toast.success('Allowlist deleted successfully')
      queryClient.invalidateQueries({ queryKey: ['allowlists'] })
    },
    onError: (error: AxiosErrorResponse) => {
      toast.error(error.response?.data?.error || 'Failed to delete allowlist')
    },
  })

  const handleCreateAllowlist = (e: React.FormEvent) => {
    e.preventDefault()
    if (!newAllowlistName.trim() || !newAllowlistDescription.trim()) {
      toast.error('Please fill in all fields')
      return
    }
    createMutation.mutate({ name: newAllowlistName, description: newAllowlistDescription })
  }

  const handleInspect = (name: string) => {
    setSelectedAllowlist(name)
    setInspectDialogOpen(true)
  }

  const handleDelete = (name: string) => {
    if (confirm(`Are you sure you want to delete the allowlist "${name}"?`)) {
      deleteMutation.mutate(name)
    }
  }

  const handleAddEntries = (values: string[], expiration?: string, description?: string) => {
    if (!selectedAllowlist) {
      toast.error('Please select an allowlist')
      return
    }
    addEntriesMutation.mutate({
      allowlist_name: selectedAllowlist,
      values,
      expiration,
      description,
    })
  }

  const handleRemoveEntries = (values: string[]) => {
    if (!selectedAllowlist) {
      toast.error('Please select an allowlist')
      return
    }
    removeEntriesMutation.mutate({ allowlist_name: selectedAllowlist, values })
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="CrowdSec Allowlist Management"
        description="Manage IP-based allowlists at the LAPI level. Allowlists affect local decisions, blocklist pulls, and WAF/AppSec."
      />

      {isError && <QueryError error={error} onRetry={refetch} />}

      <Alert>
        <Info className="h-4 w-4" />
        <AlertTitle>About Allowlists vs Whitelists</AlertTitle>
        <AlertDescription>
          <strong>Allowlists</strong> are CrowdSec's centralized IP-based filtering at the LAPI level, affecting all security decisions.
          They only support IPs and CIDR ranges. For more granular filtering based on URLs or other log elements, use Parser Whitelists or Profile Rules.
          <br /><br />
          The <strong>Whitelist</strong> feature manages both CrowdSec and Traefik whitelists together, offering a simpler approach if you don't need centralized LAPI-level allowlists.
        </AlertDescription>
      </Alert>

      {showNoAllowlistOption && allowlistsData?.length === 0 && (
        <Card className="border-primary/50">
          <CardHeader>
            <CardTitle>Don't Need Allowlists?</CardTitle>
            <CardDescription>
              If you prefer simpler whitelist management without LAPI-level allowlists, you can use the Whitelist feature instead.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Allowlists provide centralized control at the CrowdSec LAPI level, but if you just want to whitelist IPs for CrowdSec and Traefik,
              the Whitelist page offers a simpler interface.
            </p>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => window.location.href = '/whitelist'}>Go to Whitelist Page</Button>
              <Button variant="ghost" onClick={() => setShowNoAllowlistOption(false)}>Continue with Allowlists</Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Allowlists</CardTitle>
              <CardDescription>Create and manage CrowdSec allowlists</CardDescription>
            </div>
            <div className="flex gap-2">
              <Badge variant="secondary">{allowlistsData?.length || 0}</Badge>
              <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isLoading}>
                <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
              <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
                <DialogTrigger asChild>
                  <Button size="sm"><Plus className="h-4 w-4" />Create Allowlist</Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Create New Allowlist</DialogTitle>
                    <DialogDescription>Create a new allowlist to manage IP-based filtering</DialogDescription>
                  </DialogHeader>
                  <form onSubmit={handleCreateAllowlist} className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="name">Allowlist Name</Label>
                      <Input id="name" placeholder="my-allowlist" value={newAllowlistName} onChange={(e) => setNewAllowlistName(e.target.value)} required />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="description">Description</Label>
                      <Input id="description" placeholder="Trusted IPs for production environment" value={newAllowlistDescription} onChange={(e) => setNewAllowlistDescription(e.target.value)} required />
                    </div>
                    <DialogFooter>
                      <Button type="submit" disabled={createMutation.isPending}>
                        {createMutation.isPending ? 'Creating...' : 'Create Allowlist'}
                      </Button>
                    </DialogFooter>
                  </form>
                </DialogContent>
              </Dialog>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
              <span className="ml-2 text-muted-foreground">Loading allowlists...</span>
            </div>
          ) : allowlistsData && allowlistsData.length > 0 ? (
            <div className="rounded-md border">
              <div className="px-4 py-2">
                <ResultsSummary total={allowlistsData.length} label="allowlists" />
              </div>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Description</TableHead>
                    <TableHead>Created At</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {allowlistsData.map((allowlist: AllowlistType) => (
                    <TableRow key={allowlist.name}>
                      <TableCell className="font-medium">{allowlist.name}</TableCell>
                      <TableCell>{allowlist.description}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {allowlist.created_at ? new Date(allowlist.created_at).toLocaleString() : 'N/A'}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button variant="outline" size="sm" onClick={() => handleInspect(allowlist.name)}>
                            <Eye className="h-4 w-4" />Inspect
                          </Button>
                          <Button variant="destructive" size="sm" onClick={() => handleDelete(allowlist.name)}>
                            <Trash2 className="h-4 w-4" />Delete
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <EmptyState
              icon={ListChecks}
              title="No allowlists found"
              description="Create your first allowlist to start managing IP-based filtering"
            />
          )}
        </CardContent>
      </Card>

      {allowlistsData && allowlistsData.length > 0 && (
        <ManageEntries
          allowlists={allowlistsData}
          selectedAllowlist={selectedAllowlist}
          onSelectAllowlist={setSelectedAllowlist}
          onAddEntries={handleAddEntries}
          onRemoveEntries={handleRemoveEntries}
          isAdding={addEntriesMutation.isPending}
          isRemoving={removeEntriesMutation.isPending}
        />
      )}

      <InspectDialog
        open={inspectDialogOpen}
        onOpenChange={setInspectDialogOpen}
        allowlistName={selectedAllowlist}
        data={inspectData}
        isLoading={isInspecting}
      />
    </div>
  )
}
