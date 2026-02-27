import { Fragment, useEffect, useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { hubAPI } from '@/lib/api/hub'
import { ErrorContexts, getErrorMessage } from '@/lib/api/errors'
import { useSearch } from '@/contexts/SearchContext'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Search, Download, Trash2, RefreshCw, Package, Info } from 'lucide-react'
import { PageHeader, EmptyState, PageLoader, QueryError, ResultsSummary } from '@/components/common'

type HubItemType = 'collections' | 'scenarios' | 'parsers' | 'postoverflows' | 'appsec-configs' | 'appsec-rules' | 'contexts'

type HubBrowserItem = {
  name: string
  status: string
  version?: string
  local_version?: string
  local_path?: string
  description?: string
  author?: string
  utf8_status?: string
}

const HUB_TABS: { value: HubItemType; label: string }[] = [
  { value: 'collections', label: 'Collections' },
  { value: 'scenarios', label: 'Scenarios' },
  { value: 'parsers', label: 'Parsers' },
  { value: 'postoverflows', label: 'Postoverflows' },
  { value: 'appsec-configs', label: 'AppSec Configs' },
  { value: 'appsec-rules', label: 'AppSec Rules' },
  { value: 'contexts', label: 'Contexts' },
]

const EMPTY_HUB_ITEMS: Record<HubItemType, HubBrowserItem[]> = {
  collections: [],
  scenarios: [],
  parsers: [],
  postoverflows: [],
  'appsec-configs': [],
  'appsec-rules': [],
  contexts: [],
}

function statusBadge(status: string) {
  if (status === 'enabled') return <Badge variant="default">Enabled</Badge>
  if (status === 'disabled') return <Badge variant="secondary">Disabled</Badge>
  return <Badge variant="outline">{status}</Badge>
}

type ParsedHubItems = {
  items: Record<HubItemType, HubBrowserItem[]>
  rawParseError: boolean
}

function extractHubArray(record: Record<string, unknown>, ...keys: string[]): HubBrowserItem[] {
  for (const key of keys) {
    if (Array.isArray(record[key])) return record[key] as HubBrowserItem[]
  }
  return []
}

function parseHubJSONString(raw: string): unknown {
  const trimmed = raw.trim()
  if (!trimmed) return null

  try {
    return JSON.parse(trimmed)
  } catch {
    // Continue with robust fallback below.
  }

  const firstObject = trimmed.indexOf('{')
  const firstArray = trimmed.indexOf('[')

  let start = -1
  if (firstObject >= 0 && firstArray >= 0) start = Math.min(firstObject, firstArray)
  else if (firstObject >= 0) start = firstObject
  else if (firstArray >= 0) start = firstArray

  if (start < 0) {
    throw new Error('No JSON payload found in hub response')
  }

  const openChar = trimmed[start]
  const closeChar = openChar === '{' ? '}' : ']'
  for (let end = trimmed.length - 1; end > start; end -= 1) {
    if (trimmed[end] !== closeChar) continue
    const candidate = trimmed.slice(start, end + 1)
    try {
      return JSON.parse(candidate)
    } catch {
      // Keep shrinking until we find a parseable payload.
    }
  }

  throw new Error('Unable to parse JSON payload from hub response')
}

function parseHubItems(data: unknown): ParsedHubItems {
  if (!data) return { items: EMPTY_HUB_ITEMS, rawParseError: false }
  if (Array.isArray(data)) {
    return { items: { ...EMPTY_HUB_ITEMS, scenarios: data as HubBrowserItem[] }, rawParseError: false }
  }
  if (typeof data === 'string') {
    try {
      const parsed = parseHubJSONString(data)
      return parseHubItems(parsed)
    } catch {
      return { items: EMPTY_HUB_ITEMS, rawParseError: true }
    }
  }
  if (typeof data === 'object') {
    const record = data as Record<string, unknown>
    return {
      rawParseError: false,
      items: {
        collections: extractHubArray(record, 'collections'),
        scenarios: extractHubArray(record, 'scenarios'),
        parsers: extractHubArray(record, 'parsers'),
        postoverflows: extractHubArray(record, 'postoverflows'),
        'appsec-configs': extractHubArray(record, 'appsec-configs', 'appsec_configs'),
        'appsec-rules': extractHubArray(record, 'appsec-rules', 'appsec_rules'),
        contexts: extractHubArray(record, 'contexts'),
      },
    }
  }
  return { items: EMPTY_HUB_ITEMS, rawParseError: false }
}

export default function HubBrowser() {
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()
  const { query, setQuery } = useSearch()
  const [activeTab, setActiveTab] = useState<HubItemType>(() => {
    const tab = searchParams.get('tab') as HubItemType | null
    return tab && HUB_TABS.some((entry) => entry.value === tab) ? tab : 'collections'
  })
  const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set())

  const toggleExpanded = (name: string) => {
    setExpandedItems((prev) => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })
  }

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['hub-items-browser'],
    queryFn: async () => {
      const response = await hubAPI.list()
      return response.data.data ?? null
    },
  })

  const installMutation = useMutation({
    mutationFn: ({ name, type }: { name: string; type: HubItemType }) => hubAPI.install(type, { item_name: name }),
    onSuccess: () => {
      toast.success('Hub item installed successfully')
      queryClient.invalidateQueries({ queryKey: ['hub-items-browser'] })
    },
    onError: (err) => toast.error(getErrorMessage(err, 'Failed to install hub item', ErrorContexts.HubInstall)),
  })

  const removeMutation = useMutation({
    mutationFn: ({ name, type }: { name: string; type: HubItemType }) => hubAPI.remove(type, { item_name: name }),
    onSuccess: () => {
      toast.success('Hub item removed successfully')
      queryClient.invalidateQueries({ queryKey: ['hub-items-browser'] })
    },
    onError: (err) => toast.error(getErrorMessage(err, 'Failed to remove hub item', ErrorContexts.HubRemove)),
  })

  const upgradeAllMutation = useMutation({
    mutationFn: () => hubAPI.upgradeAll(),
    onSuccess: () => {
      toast.success('All hub items upgraded')
      queryClient.invalidateQueries({ queryKey: ['hub-items-browser'] })
    },
    onError: (err) => toast.error(getErrorMessage(err, 'Failed to upgrade hub items', ErrorContexts.HubUpgradeAll)),
  })

  const { items: hubItemsByType, rawParseError } = useMemo(() => parseHubItems(data), [data])
  const activeItems = useMemo(() => hubItemsByType[activeTab] || [], [hubItemsByType, activeTab])

  const filteredItems = useMemo(() => {
    const lower = query.toLowerCase()
    return activeItems.filter((item) => {
      if (!lower) return true
      return (
        item.name.toLowerCase().includes(lower) ||
        item.description?.toLowerCase().includes(lower) ||
        item.author?.toLowerCase().includes(lower)
      )
    })
  }, [activeItems, query])

  useEffect(() => {
    const currentTab = searchParams.get('tab') ?? ''
    const currentQ = searchParams.get('q') ?? ''
    if (currentTab === activeTab && currentQ === query) return

    const next = new URLSearchParams(searchParams)
    if (query) next.set('q', query)
    else next.delete('q')
    next.set('tab', activeTab)
    setSearchParams(next, { replace: true })
  }, [query, activeTab, searchParams, setSearchParams])

  return (
    <div className="space-y-6">
      <PageHeader
        title="Hub Browser"
        description="Overview of hub items with install/remove and upgrade-all actions"
        breadcrumbs="Hub / Browser"
      />

      {isError && <QueryError error={error} onRetry={refetch} />}

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Package className="h-5 w-5" />
              <div>
                <CardTitle>Hub Items Overview</CardTitle>
                <CardDescription>Legacy overview and quick maintenance actions.</CardDescription>
              </div>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isLoading}>
                <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
              <Button size="sm" onClick={() => upgradeAllMutation.mutate()} disabled={upgradeAllMutation.isPending}>
                <Download className="h-4 w-4 mr-2" />
                {upgradeAllMutation.isPending ? 'Upgrading...' : 'Update Hub'}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {rawParseError && (
            <Alert>
              <AlertTitle>Hub response format issue</AlertTitle>
              <AlertDescription>
                The hub list response could not be parsed. Items may appear empty until the response is fixed.
              </AlertDescription>
            </Alert>
          )}

          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search hub items by name, description, or author..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="pl-10"
            />
          </div>

          <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as HubItemType)}>
            <TabsList>
              {HUB_TABS.map((tab) => (
                <TabsTrigger key={tab.value} value={tab.value}>{tab.label}</TabsTrigger>
              ))}
            </TabsList>

            {HUB_TABS.map((tab) => (
              <TabsContent key={tab.value} value={tab.value}>
                {isLoading ? (
                  <PageLoader message="Loading hub items..." />
                ) : filteredItems.length > 0 ? (
                  <div className="rounded-md border">
                    <div className="px-4 py-2">
                      <ResultsSummary
                        total={activeItems.length}
                        filtered={filteredItems.length}
                        label="items"
                        query={query || undefined}
                      />
                    </div>
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
                          <Fragment key={item.name}>
                            <TableRow>
                              <TableCell>
                                <div>
                                  <p className="font-mono text-sm font-medium">{item.name}</p>
                                  {item.description && (
                                    <p className="text-xs text-muted-foreground mt-1 max-w-md truncate">{item.description}</p>
                                  )}
                                </div>
                              </TableCell>
                              <TableCell>{statusBadge(item.status)}</TableCell>
                              <TableCell className="text-sm text-muted-foreground">{item.local_version || item.version || '-'}</TableCell>
                              <TableCell className="text-sm text-muted-foreground">{item.author || '-'}</TableCell>
                              <TableCell className="text-right">
                                <div className="flex items-center justify-end gap-1">
                                  <Button variant="ghost" size="sm" onClick={() => toggleExpanded(item.name)}>
                                    <Info className="h-4 w-4" />
                                  </Button>
                                  {item.status === 'enabled' ? (
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => removeMutation.mutate({ name: item.name, type: tab.value })}
                                      disabled={removeMutation.isPending}
                                    >
                                      <Trash2 className="h-4 w-4 text-destructive" />
                                    </Button>
                                  ) : (
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => installMutation.mutate({ name: item.name, type: tab.value })}
                                      disabled={installMutation.isPending}
                                    >
                                      <Download className="h-4 w-4" />
                                    </Button>
                                  )}
                                </div>
                              </TableCell>
                            </TableRow>
                            {expandedItems.has(item.name) && (
                              <TableRow>
                                <TableCell colSpan={5} className="bg-muted/30">
                                  <div className="grid gap-2 text-xs text-muted-foreground sm:grid-cols-2">
                                    <div><span className="font-medium text-foreground">Description:</span> {item.description || 'No description available'}</div>
                                    <div><span className="font-medium text-foreground">Author:</span> {item.author || 'Unknown'}</div>
                                    <div><span className="font-medium text-foreground">Local Path:</span> {item.local_path || 'N/A'}</div>
                                    <div><span className="font-medium text-foreground">Version:</span> {item.local_version || item.version || '-'}</div>
                                  </div>
                                </TableCell>
                              </TableRow>
                            )}
                          </Fragment>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                ) : (
                  <EmptyState icon={Package} title="No items found" description={query ? 'Try adjusting your search' : 'No hub items available'} />
                )}
              </TabsContent>
            ))}
          </Tabs>
        </CardContent>
      </Card>
    </div>
  )
}
