import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { hubAPI } from '@/lib/api/hub'
import type { HubItem } from '@/lib/api/hub'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Search, Download, Trash2, RefreshCw, Package } from 'lucide-react'
import { PageHeader, EmptyState, PageLoader, QueryError } from '@/components/common'

type HubItemType = 'scenarios' | 'parsers' | 'collections' | 'postoverflows'

const HUB_TABS: { value: HubItemType; label: string }[] = [
  { value: 'scenarios', label: 'Scenarios' },
  { value: 'parsers', label: 'Parsers' },
  { value: 'collections', label: 'Collections' },
  { value: 'postoverflows', label: 'Postoverflows' },
]

function statusBadge(status: string) {
  if (status === 'enabled') return <Badge variant="default">Enabled</Badge>
  if (status === 'disabled') return <Badge variant="secondary">Disabled</Badge>
  return <Badge variant="outline">{status}</Badge>
}

export default function Hub() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [activeTab, setActiveTab] = useState<HubItemType>('scenarios')

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['hub-items'],
    queryFn: async () => {
      const response = await hubAPI.list()
      return response.data.data as HubItem[]
    },
  })

  const installMutation = useMutation({
    mutationFn: ({ name, type }: { name: string; type: HubItemType }) =>
      hubAPI.install({ name, type }),
    onSuccess: () => {
      toast.success('Hub item installed successfully')
      queryClient.invalidateQueries({ queryKey: ['hub-items'] })
    },
    onError: () => toast.error('Failed to install hub item'),
  })

  const removeMutation = useMutation({
    mutationFn: ({ name, type }: { name: string; type: HubItemType }) =>
      hubAPI.remove({ name, type }),
    onSuccess: () => {
      toast.success('Hub item removed successfully')
      queryClient.invalidateQueries({ queryKey: ['hub-items'] })
    },
    onError: () => toast.error('Failed to remove hub item'),
  })

  const upgradeAllMutation = useMutation({
    mutationFn: () => hubAPI.upgradeAll(),
    onSuccess: () => {
      toast.success('All hub items upgraded')
      queryClient.invalidateQueries({ queryKey: ['hub-items'] })
    },
    onError: () => toast.error('Failed to upgrade hub items'),
  })

  const filteredItems = useMemo(() => {
    if (!data) return []
    const lowerSearch = search.toLowerCase()
    return data.filter((item) => {
      const matchesSearch =
        !lowerSearch ||
        item.name.toLowerCase().includes(lowerSearch) ||
        item.description?.toLowerCase().includes(lowerSearch) ||
        item.author?.toLowerCase().includes(lowerSearch)
      return matchesSearch
    })
  }, [data, search])

  return (
    <div className="space-y-6">
      <PageHeader
        title="CrowdSec Hub"
        description="Browse, install, and manage CrowdSec hub items"
      />

      {isError && <QueryError error={error} onRetry={refetch} />}

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Package className="h-5 w-5" />
              <div>
                <CardTitle>Hub Items</CardTitle>
                <CardDescription>
                  {data?.length || 0} items available
                </CardDescription>
              </div>
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => refetch()}
                disabled={isLoading}
              >
                <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
              <Button
                size="sm"
                onClick={() => upgradeAllMutation.mutate()}
                disabled={upgradeAllMutation.isPending}
              >
                <Download className="h-4 w-4 mr-2" />
                {upgradeAllMutation.isPending ? 'Upgrading...' : 'Upgrade All'}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search hub items by name, description, or author..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-10"
            />
          </div>

          <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as HubItemType)}>
            <TabsList>
              {HUB_TABS.map((tab) => (
                <TabsTrigger key={tab.value} value={tab.value}>
                  {tab.label}
                </TabsTrigger>
              ))}
            </TabsList>

            {HUB_TABS.map((tab) => (
              <TabsContent key={tab.value} value={tab.value}>
                {isLoading ? (
                  <PageLoader message="Loading hub items..." />
                ) : filteredItems.length > 0 ? (
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Name</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Version</TableHead>
                          <TableHead>Author</TableHead>
                          <TableHead className="text-right">Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredItems.map((item) => (
                          <TableRow key={item.name}>
                            <TableCell>
                              <div>
                                <p className="font-mono text-sm font-medium">{item.name}</p>
                                {item.description && (
                                  <p className="text-xs text-muted-foreground mt-1 max-w-md truncate">
                                    {item.description}
                                  </p>
                                )}
                              </div>
                            </TableCell>
                            <TableCell>{statusBadge(item.status)}</TableCell>
                            <TableCell className="text-sm text-muted-foreground">
                              {item.local_version || item.version}
                            </TableCell>
                            <TableCell className="text-sm text-muted-foreground">
                              {item.author || '-'}
                            </TableCell>
                            <TableCell className="text-right">
                              {item.status === 'enabled' ? (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() =>
                                    removeMutation.mutate({ name: item.name, type: tab.value })
                                  }
                                  disabled={removeMutation.isPending}
                                >
                                  <Trash2 className="h-4 w-4 text-destructive" />
                                </Button>
                              ) : (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() =>
                                    installMutation.mutate({ name: item.name, type: tab.value })
                                  }
                                  disabled={installMutation.isPending}
                                >
                                  <Download className="h-4 w-4" />
                                </Button>
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                ) : (
                  <EmptyState
                    icon={Package}
                    title="No items found"
                    description={search ? 'Try adjusting your search' : 'No hub items available'}
                  />
                )}
              </TabsContent>
            ))}
          </Tabs>
        </CardContent>
      </Card>
    </div>
  )
}
