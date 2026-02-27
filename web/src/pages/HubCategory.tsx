import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { hubAPI, type HubCategoryItem, type HubCategoryKey } from '@/lib/api/hub'
import { ErrorContexts, getErrorMessage } from '@/lib/api/errors'
import { PageHeader, EmptyState, QueryError, PageLoader } from '@/components/common'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Textarea } from '@/components/ui/textarea'
import { Package } from 'lucide-react'

const categoryMeta: Record<HubCategoryKey, { title: string; breadcrumbs: string }> = {
  collections: { title: 'Collections', breadcrumbs: 'Hub / Collections' },
  scenarios: { title: 'Attack scenarios', breadcrumbs: 'Hub / Attack scenarios' },
  parsers: { title: 'Log parsers', breadcrumbs: 'Hub / Log parsers' },
  postoverflows: { title: 'Postoverflows', breadcrumbs: 'Hub / Postoverflows' },
  remediations: { title: 'Remediation components', breadcrumbs: 'Hub / Remediations' },
  'appsec-configs': { title: 'AppSec configurations', breadcrumbs: 'Hub / AppSec configurations' },
  'appsec-rules': { title: 'AppSec rules', breadcrumbs: 'Hub / AppSec rules' },
  contexts: { title: 'Contexts', breadcrumbs: 'Hub / Contexts' },
}

function isHubCategoryKey(value: string): value is HubCategoryKey {
  return Object.prototype.hasOwnProperty.call(categoryMeta, value)
}

function parseItems(raw: unknown): HubCategoryItem[] {
  if (!raw) return []
  if (Array.isArray(raw)) return raw as HubCategoryItem[]
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw)
      return parseItems(parsed)
    } catch {
      return []
    }
  }
  if (typeof raw === 'object') {
    const record = raw as Record<string, unknown>
    for (const value of Object.values(record)) {
      if (Array.isArray(value)) return value as HubCategoryItem[]
    }
  }
  return []
}

export default function HubCategory() {
  const params = useParams<{ category: string }>()
  const queryClient = useQueryClient()

  const categoryParam = (params.category || '').toLowerCase()
  const isValidCategory = isHubCategoryKey(categoryParam)
  const category = isValidCategory ? categoryParam : null

  const [itemName, setItemName] = useState('')
  const [filename, setFilename] = useState('custom.yaml')
  const [yaml, setYAML] = useState('')
  const [targetPath, setTargetPath] = useState('')
  const [mode, setMode] = useState<'direct' | 'manual'>('direct')

  const { data: itemsData, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['hub-category-items', category],
    queryFn: async () => {
      if (!category) return null
      const response = await hubAPI.listItems(category)
      return response.data.data ?? null
    },
    enabled: !!category,
  })

  const { data: preferenceData, refetch: refetchPreference } = useQuery({
    queryKey: ['hub-category-preference', category],
    queryFn: async () => {
      if (!category) return null
      const response = await hubAPI.getPreference(category)
      return response.data.data ?? null
    },
    enabled: !!category,
  })

  const { data: historyData } = useQuery({
    queryKey: ['hub-category-history', category],
    queryFn: async () => {
      if (!category) return []
      const response = await hubAPI.listHistory({ category, limit: 20 })
      return response.data.data ?? []
    },
    enabled: !!category,
  })

  const items = useMemo(() => parseItems(itemsData?.items), [itemsData])
  const containerDir = itemsData?.category?.container_dir || ''

  const refreshAll = () => {
    queryClient.invalidateQueries({ queryKey: ['hub-category-items', category] })
    queryClient.invalidateQueries({ queryKey: ['hub-category-history', category] })
    queryClient.invalidateQueries({ queryKey: ['hub-category-preference', category] })
  }

  const installMutation = useMutation({
    mutationFn: (name: string) => {
      if (!category) throw new Error('Invalid category')
      return hubAPI.install(category, { item_name: name })
    },
    onSuccess: () => {
      toast.success('Hub item installed')
      setItemName('')
      refreshAll()
    },
    onError: (err) => toast.error(getErrorMessage(err, 'Failed to install hub item', ErrorContexts.HubInstall)),
  })

  const removeMutation = useMutation({
    mutationFn: (name: string) => {
      if (!category) throw new Error('Invalid category')
      return hubAPI.remove(category, { item_name: name })
    },
    onSuccess: () => {
      toast.success('Hub item removed')
      refreshAll()
    },
    onError: (err) => toast.error(getErrorMessage(err, 'Failed to remove hub item', ErrorContexts.HubRemove)),
  })

  const manualApplyMutation = useMutation({
    mutationFn: () => {
      if (!category) throw new Error('Invalid category')
      return hubAPI.manualApply(category, {
        filename,
        yaml,
        target_path: targetPath.trim() || undefined,
      })
    },
    onSuccess: () => {
      toast.success('YAML applied successfully')
      refreshAll()
    },
    onError: (err) => toast.error(getErrorMessage(err, 'Failed to apply YAML', ErrorContexts.HubInstall)),
  })

  const savePreferenceMutation = useMutation({
    mutationFn: (payload: { default_mode: 'direct' | 'manual'; default_yaml_path?: string }) => {
      if (!category) throw new Error('Invalid category')
      return hubAPI.updatePreference(category, payload)
    },
    onSuccess: async () => {
      toast.success('Preference saved')
      await refetchPreference()
    },
    onError: (err) => toast.error(getErrorMessage(err, 'Failed to save preference', ErrorContexts.HubInstall)),
  })

  if (!category || !isValidCategory) {
    return (
      <div className="space-y-6">
        <PageHeader title="Hub" description="Invalid category" breadcrumbs="Hub" />
        <EmptyState icon={Package} title="Invalid hub category" description="Choose a valid Hub category from the sidebar." />
      </div>
    )
  }

  const meta = categoryMeta[category]

  return (
    <div className="space-y-6">
      <PageHeader
        title={meta.title}
        description="Install via direct cscli action or apply YAML manually"
        breadcrumbs={meta.breadcrumbs}
      />

      {isError && <QueryError error={error} onRetry={refetch} />}

      {containerDir && (
        <Card>
          <CardContent className="py-3">
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
              <span className="text-muted-foreground">Container path helper</span>
              <code className="rounded bg-muted px-2 py-1 text-xs">{containerDir}</code>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Installed Items</CardTitle>
          <CardDescription>Current items reported by cscli for this category.</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <PageLoader message="Loading hub category items..." />
          ) : items.length === 0 ? (
            <EmptyState icon={Package} title="No items found" description="Install an item or apply YAML to get started." />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((item) => (
                  <TableRow key={item.name}>
                    <TableCell className="font-mono text-sm">{item.name}</TableCell>
                    <TableCell>
                      <Badge variant={item.status === 'enabled' ? 'default' : 'secondary'}>{item.status || 'unknown'}</Badge>
                    </TableCell>
                    <TableCell>{item.local_version || item.version || '-'}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => removeMutation.mutate(item.name)}
                        disabled={removeMutation.isPending}
                      >
                        Remove
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Install Mode</CardTitle>
          <CardDescription>Choose direct installation or manual YAML apply.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Tabs value={mode} onValueChange={(v) => setMode(v as 'direct' | 'manual')}>
            <TabsList>
              <TabsTrigger value="direct">Direct install</TabsTrigger>
              <TabsTrigger value="manual">Manual YAML</TabsTrigger>
            </TabsList>

            <TabsContent value="direct" className="space-y-3">
              <div className="space-y-2">
                <Label htmlFor="hub-item-name">Hub item name</Label>
                <Input
                  id="hub-item-name"
                  placeholder="LePresidente/adguardhome"
                  value={itemName}
                  onChange={(e) => setItemName(e.target.value)}
                />
              </div>
              <div className="flex gap-2">
                <Button
                  onClick={() => installMutation.mutate(itemName.trim())}
                  disabled={!itemName.trim() || installMutation.isPending}
                >
                  {installMutation.isPending ? 'Installing...' : 'Install'}
                </Button>
                <Button
                  variant="outline"
                  onClick={() =>
                    savePreferenceMutation.mutate({ default_mode: 'direct', default_yaml_path: preferenceData?.default_yaml_path })
                  }
                  disabled={savePreferenceMutation.isPending}
                >
                  Save As Default
                </Button>
              </div>
            </TabsContent>

            <TabsContent value="manual" className="space-y-3">
              <div className="grid gap-3 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="hub-yaml-file">Filename</Label>
                  <Input
                    id="hub-yaml-file"
                    placeholder="custom.yaml"
                    value={filename}
                    onChange={(e) => setFilename(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="hub-yaml-target">Target path (optional)</Label>
                  <Input
                    id="hub-yaml-target"
                    placeholder={preferenceData?.default_yaml_path || '/etc/crowdsec/<category>/file.yaml'}
                    value={targetPath}
                    onChange={(e) => setTargetPath(e.target.value)}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="hub-yaml-content">YAML box</Label>
                <Textarea
                  id="hub-yaml-content"
                  placeholder="Paste YAML content to apply"
                  value={yaml}
                  onChange={(e) => setYAML(e.target.value)}
                  className="min-h-[220px] font-mono text-sm"
                />
              </div>
              <div className="flex gap-2">
                <Button
                  onClick={() => manualApplyMutation.mutate()}
                  disabled={!yaml.trim() || !filename.trim() || manualApplyMutation.isPending}
                >
                  {manualApplyMutation.isPending ? 'Applying...' : 'Apply YAML'}
                </Button>
                <Button
                  variant="outline"
                  onClick={() =>
                    savePreferenceMutation.mutate({
                      default_mode: 'manual',
                      default_yaml_path: targetPath.trim() || preferenceData?.default_yaml_path,
                    })
                  }
                  disabled={savePreferenceMutation.isPending}
                >
                  Save As Default
                </Button>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Operation History</CardTitle>
          <CardDescription>Recent category operations are persisted in DB.</CardDescription>
        </CardHeader>
        <CardContent>
          {!historyData || historyData.length === 0 ? (
            <p className="text-sm text-muted-foreground">No operations recorded yet.</p>
          ) : (
            <div className="space-y-2">
              {historyData.map((entry) => (
                <div key={entry.id} className="rounded border p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="text-sm font-medium">
                      {entry.action} - {entry.item_name || entry.yaml_path || '-'}
                    </div>
                    <Badge variant={entry.success ? 'default' : 'destructive'}>{entry.success ? 'success' : 'failed'}</Badge>
                  </div>
                  <div className="mt-2 text-xs text-muted-foreground">
                    <div>Mode: {entry.mode}</div>
                    <div>When: {entry.created_at || '-'}</div>
                    {entry.command && <div>Command: {entry.command}</div>}
                    {entry.error && <div>Error: {entry.error}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
