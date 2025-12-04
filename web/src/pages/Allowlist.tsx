import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { AllowlistCreateRequest, AllowlistAddEntriesRequest, AllowlistRemoveEntriesRequest } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { AlertCircle, Shield, Plus, Trash2, Eye, RefreshCw, Info, ListChecks } from 'lucide-react'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert'

export default function Allowlist() {
  const queryClient = useQueryClient()

  // Form states
  const [newAllowlistName, setNewAllowlistName] = useState('')
  const [newAllowlistDescription, setNewAllowlistDescription] = useState('')
  const [selectedAllowlist, setSelectedAllowlist] = useState<string>('')
  const [ipsToAdd, setIpsToAdd] = useState('')
  const [entryDescription, setEntryDescription] = useState('')
  const [expiration, setExpiration] = useState('')
  const [ipsToRemove, setIpsToRemove] = useState('')
  const [inspectDialogOpen, setInspectDialogOpen] = useState(false)
  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [showNoAllowlistOption, setShowNoAllowlistOption] = useState(true)

  // Queries
  const { data: allowlistsData, isLoading, refetch } = useQuery({
    queryKey: ['allowlists'],
    queryFn: async () => {
      const response = await api.allowlist.list()
      // Handle both array (legacy) and object (new) formats
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

  // Mutations
  const createMutation = useMutation({
    mutationFn: (data: AllowlistCreateRequest) => api.allowlist.create(data),
    onSuccess: () => {
      toast.success('Allowlist created successfully')
      setNewAllowlistName('')
      setNewAllowlistDescription('')
      setCreateDialogOpen(false)
      queryClient.invalidateQueries({ queryKey: ['allowlists'] })
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to create allowlist')
    },
  })

  const addEntriesMutation = useMutation({
    mutationFn: (data: AllowlistAddEntriesRequest) => api.allowlist.addEntries(data),
    onSuccess: () => {
      toast.success('Entries added successfully')
      setIpsToAdd('')
      setEntryDescription('')
      setExpiration('')
      queryClient.invalidateQueries({ queryKey: ['allowlist-inspect'] })
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to add entries')
    },
  })

  const removeEntriesMutation = useMutation({
    mutationFn: (data: AllowlistRemoveEntriesRequest) => api.allowlist.removeEntries(data),
    onSuccess: () => {
      toast.success('Entries removed successfully')
      setIpsToRemove('')
      queryClient.invalidateQueries({ queryKey: ['allowlist-inspect'] })
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to remove entries')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (name: string) => api.allowlist.delete(name),
    onSuccess: () => {
      toast.success('Allowlist deleted successfully')
      queryClient.invalidateQueries({ queryKey: ['allowlists'] })
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to delete allowlist')
    },
  })

  // Handlers
  const handleCreateAllowlist = (e: React.FormEvent) => {
    e.preventDefault()
    if (!newAllowlistName.trim() || !newAllowlistDescription.trim()) {
      toast.error('Please fill in all fields')
      return
    }
    createMutation.mutate({
      name: newAllowlistName,
      description: newAllowlistDescription,
    })
  }

  const handleAddEntries = (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedAllowlist || !ipsToAdd.trim()) {
      toast.error('Please select an allowlist and enter IPs')
      return
    }

    const values = ipsToAdd.split(/[,\n]/).map(ip => ip.trim()).filter(ip => ip.length > 0)

    addEntriesMutation.mutate({
      allowlist_name: selectedAllowlist,
      values,
      expiration: expiration || undefined,
      description: entryDescription || undefined,
    })
  }

  const handleRemoveEntries = (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedAllowlist || !ipsToRemove.trim()) {
      toast.error('Please select an allowlist and enter IPs to remove')
      return
    }

    const values = ipsToRemove.split(/[,\n]/).map(ip => ip.trim()).filter(ip => ip.length > 0)

    removeEntriesMutation.mutate({
      allowlist_name: selectedAllowlist,
      values,
    })
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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold flex items-center gap-2">
          <Shield className="h-8 w-8" />
          CrowdSec Allowlist Management
        </h1>
        <p className="text-muted-foreground mt-2">
          Manage IP-based allowlists at the LAPI level. Allowlists affect local decisions, blocklist pulls, and WAF/AppSec.
        </p>
      </div>

      {/* Information Card */}
      <Alert>
        <Info className="h-4 w-4" />
        <AlertTitle>About Allowlists vs Whitelists</AlertTitle>
        <AlertDescription>
          <strong>Allowlists</strong> are CrowdSec's centralized IP-based filtering at the LAPI level, affecting all security decisions.
          They only support IPs and CIDR ranges. For more granular filtering based on URLs or other log elements, use Parser Whitelists or Profile Rules.
          <br />
          <br />
          The <strong>Whitelist</strong> feature manages both CrowdSec and Traefik whitelists together, offering a simpler approach if you don't need centralized LAPI-level allowlists.
        </AlertDescription>
      </Alert>

      {/* No Allowlist Option */}
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
              <Button variant="outline" onClick={() => window.location.href = '/whitelist'}>
                Go to Whitelist Page
              </Button>
              <Button variant="ghost" onClick={() => setShowNoAllowlistOption(false)}>
                Continue with Allowlists
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Create Allowlist */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Allowlists</CardTitle>
              <CardDescription>
                Create and manage CrowdSec allowlists
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isLoading}>
                <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
              <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
                <DialogTrigger asChild>
                  <Button size="sm">
                    <Plus className="h-4 w-4 mr-2" />
                    Create Allowlist
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Create New Allowlist</DialogTitle>
                    <DialogDescription>
                      Create a new allowlist to manage IP-based filtering
                    </DialogDescription>
                  </DialogHeader>
                  <form onSubmit={handleCreateAllowlist} className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="name">Allowlist Name</Label>
                      <Input
                        id="name"
                        placeholder="my-allowlist"
                        value={newAllowlistName}
                        onChange={(e) => setNewAllowlistName(e.target.value)}
                        required
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="description">Description</Label>
                      <Input
                        id="description"
                        placeholder="Trusted IPs for production environment"
                        value={newAllowlistDescription}
                        onChange={(e) => setNewAllowlistDescription(e.target.value)}
                        required
                      />
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
                  {allowlistsData.map((allowlist: any) => (
                    <TableRow key={allowlist.name}>
                      <TableCell className="font-medium">{allowlist.name}</TableCell>
                      <TableCell>{allowlist.description}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {allowlist.created_at ? new Date(allowlist.created_at).toLocaleString() : 'N/A'}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleInspect(allowlist.name)}
                          >
                            <Eye className="h-4 w-4 mr-1" />
                            Inspect
                          </Button>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => handleDelete(allowlist.name)}
                          >
                            <Trash2 className="h-4 w-4 mr-1" />
                            Delete
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <ListChecks className="h-12 w-12 text-muted-foreground mb-4" />
              <p className="text-lg font-medium">No allowlists found</p>
              <p className="text-sm text-muted-foreground mt-2">
                Create your first allowlist to start managing IP-based filtering
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Manage Entries */}
      {allowlistsData && allowlistsData.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Manage Entries</CardTitle>
            <CardDescription>
              Add or remove IP addresses and CIDR ranges from allowlists
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="add">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="add">Add Entries</TabsTrigger>
                <TabsTrigger value="remove">Remove Entries</TabsTrigger>
              </TabsList>

              <TabsContent value="add">
                <form onSubmit={handleAddEntries} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="allowlist-select">Select Allowlist</Label>
                    <select
                      id="allowlist-select"
                      className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                      value={selectedAllowlist}
                      onChange={(e) => setSelectedAllowlist(e.target.value)}
                      required
                    >
                      <option value="">Choose an allowlist...</option>
                      {allowlistsData.map((al: any) => (
                        <option key={al.name} value={al.name}>
                          {al.name}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="ips-add">IP Addresses or CIDR Ranges</Label>
                    <textarea
                      id="ips-add"
                      className="flex min-h-[100px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                      placeholder="192.168.1.100&#10;10.0.0.0/24&#10;172.16.0.0/16"
                      value={ipsToAdd}
                      onChange={(e) => setIpsToAdd(e.target.value)}
                      required
                    />
                    <p className="text-xs text-muted-foreground">
                      Enter one IP or CIDR range per line, or separate with commas
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="expiration">Expiration (optional)</Label>
                      <Input
                        id="expiration"
                        placeholder="7d"
                        value={expiration}
                        onChange={(e) => setExpiration(e.target.value)}
                      />
                      <p className="text-xs text-muted-foreground">
                        e.g., 7d, 24h, 30d
                      </p>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="entry-desc">Description (optional)</Label>
                      <Input
                        id="entry-desc"
                        placeholder="Internal network"
                        value={entryDescription}
                        onChange={(e) => setEntryDescription(e.target.value)}
                      />
                    </div>
                  </div>

                  <Button type="submit" className="w-full" disabled={addEntriesMutation.isPending}>
                    {addEntriesMutation.isPending ? 'Adding...' : 'Add Entries'}
                  </Button>
                </form>
              </TabsContent>

              <TabsContent value="remove">
                <form onSubmit={handleRemoveEntries} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="allowlist-select-remove">Select Allowlist</Label>
                    <select
                      id="allowlist-select-remove"
                      className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                      value={selectedAllowlist}
                      onChange={(e) => setSelectedAllowlist(e.target.value)}
                      required
                    >
                      <option value="">Choose an allowlist...</option>
                      {allowlistsData.map((al: any) => (
                        <option key={al.name} value={al.name}>
                          {al.name}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="ips-remove">IP Addresses or CIDR Ranges to Remove</Label>
                    <textarea
                      id="ips-remove"
                      className="flex min-h-[100px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                      placeholder="192.168.1.100&#10;10.0.0.0/24"
                      value={ipsToRemove}
                      onChange={(e) => setIpsToRemove(e.target.value)}
                      required
                    />
                    <p className="text-xs text-muted-foreground">
                      Enter one IP or CIDR range per line, or separate with commas
                    </p>
                  </div>

                  <Button type="submit" variant="destructive" className="w-full" disabled={removeEntriesMutation.isPending}>
                    {removeEntriesMutation.isPending ? 'Removing...' : 'Remove Entries'}
                  </Button>
                </form>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}

      {/* Inspect Dialog */}
      <Dialog open={inspectDialogOpen} onOpenChange={setInspectDialogOpen}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Inspect Allowlist: {selectedAllowlist}</DialogTitle>
            <DialogDescription>
              View all entries in this allowlist
            </DialogDescription>
          </DialogHeader>
          {isInspecting ? (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
              <span className="ml-2 text-muted-foreground">Loading entries...</span>
            </div>
          ) : inspectData ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">{inspectData.name}</p>
                  <p className="text-sm text-muted-foreground">{inspectData.description}</p>
                  <div className="flex gap-4 mt-2 text-xs text-muted-foreground">
                    <span>Created: {new Date(inspectData.created_at).toLocaleString()}</span>
                    <span>Updated: {new Date(inspectData.updated_at).toLocaleString()}</span>
                  </div>
                </div>
                <Badge variant="secondary">{inspectData.count} entries</Badge>
              </div>

              {inspectData.items && inspectData.items.length > 0 ? (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Value</TableHead>
                        <TableHead>Created At</TableHead>
                        <TableHead>Expiration</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {inspectData.items.map((entry: any, idx: number) => {
                        const isNeverExpires = entry.expiration === '0001-01-01T00:00:00.000Z' || !entry.expiration
                        return (
                          <TableRow key={idx}>
                            <TableCell className="font-mono">{entry.value}</TableCell>
                            <TableCell className="text-sm text-muted-foreground">
                              {new Date(entry.created_at).toLocaleString()}
                            </TableCell>
                            <TableCell>
                              {isNeverExpires ? (
                                <Badge variant="secondary">Never</Badge>
                              ) : (
                                <span className="text-sm">{new Date(entry.expiration).toLocaleString()}</span>
                              )}
                            </TableCell>
                          </TableRow>
                        )
                      })}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-center border rounded-md">
                  <AlertCircle className="h-8 w-8 text-muted-foreground mb-2" />
                  <p className="text-sm text-muted-foreground">No entries in this allowlist</p>
                </div>
              )}
            </div>
          ) : null}
          <DialogFooter>
            <Button variant="outline" onClick={() => setInspectDialogOpen(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
