/// <reference types="vite/client" />
import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { Scenario, ScenarioSetupRequest } from '@/lib/api'
import { simulationAPI } from '@/lib/api/simulation'
import type { SimulationStatus } from '@/lib/api/simulation'
import { ErrorContexts, getErrorMessage } from '@/lib/api/errors'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { FileText, Plus, X, CheckCircle2, AlertCircle, FlaskConical } from 'lucide-react'
import { PageHeader, EmptyState, CardSkeleton } from '@/components/common'
import { useUrlFilters } from '@/hooks'

interface ScenarioItem {
  name: string
  local_version?: string
  local_path?: string
  description?: string
  utf8_status?: string
  status?: string
  version?: string
}

interface ScenariosResponse {
  scenarios?: ScenarioItem[] | string
  count?: number
}

const parseScenariosList = (data: ScenariosResponse | null | undefined): ScenarioItem[] => {
  if (!data) return []
  if (Array.isArray(data.scenarios)) {
    return (data.scenarios as unknown[]).filter(
      (item): item is ScenarioItem => item !== null && typeof item === 'object' && 'name' in (item as Record<string, unknown>)
    )
  }
  if (typeof data.scenarios === 'string') {
    try {
      const parsed = JSON.parse(data.scenarios)
      if (Array.isArray(parsed)) return parsed as ScenarioItem[]
    } catch {
      const lines = data.scenarios.split('\n').filter(line =>
        line.trim() && !line.includes('─') && !line.includes('SCENARIOS') && !line.includes('Name') && !line.includes('📦 Status')
      )
      return lines.map((line): ScenarioItem | null => {
        const parts = line.split(/\s{2,}/).filter(p => p && p !== '│')
        if (parts.length >= 2) {
          return {
            name: parts[0]?.trim() || '',
            status: parts[1]?.includes('enabled') ? 'enabled' : parts[1]?.trim(),
            version: parts[2]?.trim() || '',
            local_path: parts[3]?.trim() || ''
          }
        }
        return null
      }).filter((item): item is ScenarioItem => item !== null && item.name !== '')
    }
  }
  if (data.scenarios && typeof data.scenarios === 'object' && !Array.isArray(data.scenarios)) {
    const scenariosObj = data.scenarios as Record<string, unknown>
    if (Array.isArray(scenariosObj.scenarios)) return scenariosObj.scenarios as ScenarioItem[]
  }
  return []
}

export default function Scenarios() {
  const queryClient = useQueryClient()
  const [urlFilters, setUrlFilter] = useUrlFilters(['q'], { q: '' })
  const [scenarios, setScenarios] = useState<Scenario[]>([{ name: '', description: '', content: '' }])

  const { data: scenariosListRaw, isLoading, error, isError } = useQuery({
    queryKey: ['scenarios'],
    queryFn: async () => {
      const response = await api.scenarios.list()
      return response.data.data as ScenariosResponse | null
    },
    retry: 1,
    retryDelay: 1000,
  })

  const setupMutation = useMutation({
    mutationFn: (data: ScenarioSetupRequest) => api.scenarios.setup(data),
    onSuccess: () => {
      toast.success('Scenarios setup successfully')
      setScenarios([{ name: '', description: '', content: '' }])
      queryClient.invalidateQueries({ queryKey: ['scenarios'] })
    },
    onError: (error) => { toast.error(getErrorMessage(error, 'Failed to setup scenarios', ErrorContexts.ScenariosSetup)) },
  })

  const handleScenarioChange = (index: number, field: keyof Scenario, value: string) => {
    const newScenarios = [...scenarios]
    newScenarios[index][field] = value
    setScenarios(newScenarios)
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const validScenarios = scenarios.filter(s => s.name.trim() && s.content.trim())
    if (validScenarios.length === 0) {
      toast.error('Please add at least one valid scenario with name and content')
      return
    }
    setupMutation.mutate({ scenarios: validScenarios })
  }

  const scenariosList = parseScenariosList(scenariosListRaw)
  const filteredScenarios = useMemo(() => {
    if (!urlFilters.q) return scenariosList
    const lower = (urlFilters.q as string).toLowerCase()
    return scenariosList.filter((scenario) =>
      scenario.name?.toLowerCase().includes(lower) ||
      scenario.description?.toLowerCase().includes(lower) ||
      scenario.local_path?.toLowerCase().includes(lower)
    )
  }, [scenariosList, urlFilters.q])

  const debugInfo = useMemo(() => {
    if (!scenariosListRaw) return null
    return {
      hasData: !!scenariosListRaw, dataType: typeof scenariosListRaw,
      hasScenarios: !!scenariosListRaw.scenarios, scenariosType: typeof scenariosListRaw.scenarios,
      scenariosIsArray: Array.isArray(scenariosListRaw.scenarios),
      scenariosLength: Array.isArray(scenariosListRaw.scenarios) ? scenariosListRaw.scenarios.length : 'N/A',
      count: scenariosListRaw.count || 'N/A', parsedCount: scenariosList.length,
    }
  }, [scenariosListRaw, scenariosList])

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scenario Management"
        description="Setup and manage custom CrowdSec scenarios"
        breadcrumbs="Hub / Scenarios"
        actions={
          <Input
            placeholder="Search scenarios..."
            value={urlFilters.q as string}
            onChange={(event) => setUrlFilter('q', event.target.value)}
            className="h-9 w-56"
          />
        }
      />

      {/* Current Scenarios */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              <div>
                <CardTitle>Active Scenarios</CardTitle>
                <CardDescription>
                  Currently installed CrowdSec scenarios
                  {filteredScenarios.length > 0 && (
                    <span className="ml-2">
                      ({filteredScenarios.length} scenario{filteredScenarios.length !== 1 ? 's' : ''} found
                      {urlFilters.q ? ` of ${scenariosList.length}` : ''})
                    </span>
                  )}
                </CardDescription>
              </div>
            </div>
            {filteredScenarios.length > 0 && (
              <Badge variant="outline" className="flex items-center gap-1">
                <CheckCircle2 className="h-3 w-3" />{filteredScenarios.length} Active
              </Badge>
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {isError && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>Failed to load scenarios: {error instanceof Error ? error.message : 'Unknown error'}</AlertDescription>
            </Alert>
          )}
          {debugInfo && import.meta.env.DEV && (
            <Alert>
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                <details className="text-xs">
                  <summary className="cursor-pointer font-semibold mb-2">Debug Info (Click to expand)</summary>
                  <pre className="mt-2 p-2 bg-muted rounded overflow-x-auto">{JSON.stringify(debugInfo, null, 2)}</pre>
                </details>
              </AlertDescription>
            </Alert>
          )}
          {isLoading ? (
            <CardSkeleton lines={3} />
          ) : filteredScenarios.length > 0 ? (
            <div className="space-y-2">
              {filteredScenarios.map((scenario, index) => (
                <div key={index} className="flex items-center justify-between p-3 border rounded-lg hover:bg-accent/50 transition-colors">
                  <div className="flex-1 min-w-0">
                    <p className="font-mono font-medium text-sm truncate">{scenario.name}</p>
                    {scenario.status && (
                      <div className="flex items-center gap-2 mt-1 flex-wrap">
                        <Badge variant={scenario.status === 'enabled' ? 'default' : 'outline'}>{scenario.status}</Badge>
                        {(scenario.local_version || scenario.version) && (
                          <span className="text-xs text-muted-foreground">v{scenario.local_version || scenario.version}</span>
                        )}
                      </div>
                    )}
                  </div>
                  {scenario.local_path && (
                    <span className="text-xs text-muted-foreground font-mono ml-4 truncate max-w-xs">{scenario.local_path}</span>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={AlertCircle}
              title={urlFilters.q ? 'No scenarios matched your search' : 'No scenarios installed'}
              description={debugInfo ? 'Check the debug info above for more details' : undefined}
            />
          )}
        </CardContent>
      </Card>

      {/* Setup Custom Scenarios */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>Setup Custom Scenarios</CardTitle>
            <CardDescription>Add custom detection scenarios to CrowdSec</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {scenarios.map((scenario, index) => (
              <div key={index} className="space-y-4 p-4 border rounded-lg">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold">Scenario {index + 1}</h3>
                  {scenarios.length > 1 && (
                    <Button type="button" variant="ghost" size="sm" onClick={() => setScenarios(scenarios.filter((_, i) => i !== index))}>
                      <X className="h-4 w-4" />
                    </Button>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`name-${index}`}>Scenario Name <span className="text-destructive">*</span></Label>
                  <Input id={`name-${index}`} placeholder="e.g., custom/http-bruteforce" value={scenario.name} onChange={(e) => handleScenarioChange(index, 'name', e.target.value)} />
                  <p className="text-xs text-muted-foreground">Use format: namespace/scenario-name</p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`description-${index}`}>Description</Label>
                  <Input id={`description-${index}`} placeholder="Brief description of the scenario" value={scenario.description} onChange={(e) => handleScenarioChange(index, 'description', e.target.value)} />
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`content-${index}`}>Scenario Content (YAML) <span className="text-destructive">*</span></Label>
                  <textarea
                    id={`content-${index}`}
                    className="w-full min-h-64 p-3 text-sm font-mono border rounded-md bg-muted/50"
                    placeholder={`type: leaky\nname: custom/http-bruteforce\ndescription: Detect HTTP brute force attempts\nfilter: evt.Meta.log_type == 'http_access-log'\nleakspeed: 10s\ncapacity: 5\ngroupby: evt.Meta.source_ip\nlabels:\n  service: http\n  type: bruteforce\n  remediation: true`}
                    value={scenario.content}
                    onChange={(e) => handleScenarioChange(index, 'content', e.target.value)}
                  />
                </div>
              </div>
            ))}
            <div className="flex gap-2">
              <Button type="button" variant="outline" onClick={() => setScenarios([...scenarios, { name: '', description: '', content: '' }])} className="flex-1">
                <Plus className="h-4 w-4" />Add Another Scenario
              </Button>
              <Button type="submit" disabled={setupMutation.isPending} className="flex-1">
                {setupMutation.isPending ? 'Setting up...' : 'Setup Scenarios'}
              </Button>
            </div>
          </CardContent>
        </Card>
      </form>

      {/* Simulation Mode */}
      <SimulationCard />

      <Card>
        <CardHeader>
          <CardTitle>Example Scenario</CardTitle>
          <CardDescription>Reference example for creating custom scenarios</CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="p-4 bg-muted rounded-lg text-sm overflow-x-auto">
{`type: leaky
name: custom/http-slowloris
description: "Detect Slowloris attacks"
filter: |
  evt.Meta.log_type == 'http_access-log' &&
  evt.Meta.http_verb in ['GET', 'POST']
leakspeed: 30s
capacity: 100
groupby: evt.Meta.source_ip
labels:
  service: http
  type: slowloris
  remediation: true`}
          </pre>
        </CardContent>
      </Card>
    </div>
  )
}

function SimulationCard() {
  const queryClient = useQueryClient()

  const { data: simStatus, isLoading } = useQuery({
    queryKey: ['simulation-status'],
    queryFn: async () => {
      const response = await simulationAPI.getStatus()
      return response.data.data as SimulationStatus | null
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ scenario, enabled }: { scenario: string; enabled: boolean }) =>
      simulationAPI.toggle({ scenario, enabled }),
    onSuccess: () => {
      toast.success('Simulation mode updated')
      queryClient.invalidateQueries({ queryKey: ['simulation-status'] })
    },
    onError: (error) => toast.error(getErrorMessage(error, 'Failed to update simulation mode', ErrorContexts.ScenariosSimulationModeUpdate)),
  })

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <FlaskConical className="h-5 w-5" />
          <div>
            <CardTitle>Simulation Mode</CardTitle>
            <CardDescription>
              When enabled, scenarios run in simulation mode — alerts are generated but no actual remediation actions are taken
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {isLoading ? (
          <CardSkeleton lines={2} />
        ) : (
          <>
            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div>
                <p className="font-medium text-sm">Global Simulation</p>
                <p className="text-xs text-muted-foreground">
                  Toggle simulation mode for all scenarios at once
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant={simStatus?.global ? 'default' : 'secondary'}>
                  {simStatus?.global ? 'Enabled' : 'Disabled'}
                </Badge>
                <Switch
                  checked={simStatus?.global ?? false}
                  onCheckedChange={(checked) =>
                    toggleMutation.mutate({ scenario: '*', enabled: checked })
                  }
                  disabled={toggleMutation.isPending}
                />
              </div>
            </div>
            {simStatus?.exclusions && simStatus.exclusions.length > 0 && (
              <div>
                <p className="text-sm font-medium mb-2">Exclusions</p>
                <div className="flex flex-wrap gap-2">
                  {simStatus.exclusions.map((exc) => (
                    <Badge key={exc} variant="outline" className="font-mono text-xs">
                      {exc}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}
