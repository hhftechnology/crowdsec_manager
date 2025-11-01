import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { Scenario, ScenarioSetupRequest } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { FileText, Plus, X, CheckCircle2, AlertCircle } from 'lucide-react'

interface ScenarioItem {
  name: string
  status?: string
  version?: string
  local_path?: string
}

interface ScenariosResponse {
  scenarios?: ScenarioItem[] | string
  count?: number
}

export default function Scenarios() {
  const queryClient = useQueryClient()
  const [scenarios, setScenarios] = useState<Scenario[]>([
    { name: '', description: '', content: '' }
  ])
  const [debugInfo, setDebugInfo] = useState<any>(null)

  const { data: scenariosListRaw, isLoading, error, isError } = useQuery({
    queryKey: ['scenarios'],
    queryFn: async () => {
      try {
        const response = await api.scenarios.list()
        console.log('API Response:', response.data)
        return response.data.data as ScenariosResponse
      } catch (err) {
        console.error('Error fetching scenarios:', err)
        throw err
      }
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
    onError: () => {
      toast.error('Failed to setup scenarios')
    },
  })

  const handleAddScenario = () => {
    setScenarios([...scenarios, { name: '', description: '', content: '' }])
  }

  const handleRemoveScenario = (index: number) => {
    if (scenarios.length === 1) {
      toast.error('You must have at least one scenario')
      return
    }
    setScenarios(scenarios.filter((_, i) => i !== index))
  }

  const handleScenarioChange = (index: number, field: keyof Scenario, value: string) => {
    const newScenarios = [...scenarios]
    newScenarios[index][field] = value
    setScenarios(newScenarios)
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    // Validate scenarios
    const validScenarios = scenarios.filter(s => s.name.trim() && s.content.trim())
    if (validScenarios.length === 0) {
      toast.error('Please add at least one valid scenario with name and content')
      return
    }

    setupMutation.mutate({ scenarios: validScenarios })
  }

  // Robust parsing with comprehensive logging and type checking
  const parseScenariosList = (data: ScenariosResponse | null | undefined): ScenarioItem[] => {
    console.log('Parsing scenarios data:', data)

    if (!data) {
      console.warn('No data received')
      return []
    }

    // Check if scenarios is already an array
    if (Array.isArray(data.scenarios)) {
      console.log('Scenarios is array:', data.scenarios.length, 'items')
      return data.scenarios as ScenarioItem[]
    }

    // If scenarios is a string, try to parse it
    if (typeof data.scenarios === 'string') {
      console.log('Scenarios is string, attempting to parse')
      try {
        // Try parsing as JSON first
        const parsed = JSON.parse(data.scenarios)
        if (Array.isArray(parsed)) {
          console.log('Successfully parsed JSON from string:', parsed.length, 'items')
          return parsed as ScenarioItem[]
        }
      } catch (jsonErr) {
        console.warn('JSON parse failed, trying text parsing:', jsonErr)
        // If JSON parsing fails, parse as text table
        const scenariosStr = data.scenarios
        const lines = scenariosStr.split('\n').filter(line =>
          line.trim() &&
          !line.includes('─') &&
          !line.includes('SCENARIOS') &&
          !line.includes('Name') &&
          !line.includes('📦 Status')
        )
        const parsed = lines.map(line => {
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
        console.log('Text parsing resulted in:', parsed.length, 'items')
        return parsed
      }
    }

    console.warn('Unable to parse scenarios data, unknown format')
    return []
  }

  const scenariosList = parseScenariosList(scenariosListRaw)

  // Update debug info when data changes
  useEffect(() => {
    if (scenariosListRaw) {
      setDebugInfo({
        hasData: !!scenariosListRaw,
        dataType: typeof scenariosListRaw,
        hasScenarios: !!scenariosListRaw.scenarios,
        scenariosType: typeof scenariosListRaw.scenarios,
        scenariosIsArray: Array.isArray(scenariosListRaw.scenarios),
        scenariosLength: Array.isArray(scenariosListRaw.scenarios)
          ? scenariosListRaw.scenarios.length
          : 'N/A',
        count: scenariosListRaw.count || 'N/A',
        parsedCount: scenariosList.length,
      })
    }
  }, [scenariosListRaw, scenariosList])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Scenario Management</h1>
        <p className="text-muted-foreground mt-2">
          Setup and manage custom CrowdSec scenarios
        </p>
      </div>

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
                  {scenariosList.length > 0 && (
                    <span className="ml-2">
                      ({scenariosList.length} scenario{scenariosList.length !== 1 ? 's' : ''} found)
                    </span>
                  )}
                </CardDescription>
              </div>
            </div>
            {scenariosList.length > 0 && (
              <Badge variant="outline" className="flex items-center gap-1">
                <CheckCircle2 className="h-3 w-3" />
                {scenariosList.length} Active
              </Badge>
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Error alert */}
          {isError && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                Failed to load scenarios: {error instanceof Error ? error.message : 'Unknown error'}
              </AlertDescription>
            </Alert>
          )}

          {/* Debug panel (development only) */}
          {debugInfo && process.env.NODE_ENV === 'development' && (
            <Alert>
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                <details className="text-xs">
                  <summary className="cursor-pointer font-semibold mb-2">Debug Info (Click to expand)</summary>
                  <pre className="mt-2 p-2 bg-muted rounded overflow-x-auto">
                    {JSON.stringify(debugInfo, null, 2)}
                  </pre>
                </details>
              </AlertDescription>
            </Alert>
          )}

          {isLoading ? (
            <div className="space-y-2">
              <div className="h-12 bg-muted animate-pulse rounded" />
              <div className="h-12 bg-muted animate-pulse rounded" />
              <div className="h-12 bg-muted animate-pulse rounded" />
            </div>
          ) : scenariosList.length > 0 ? (
            <div className="space-y-2 max-h-[400px] overflow-y-auto">
              {scenariosList.map((scenario, index) => (
                <div key={index} className="flex items-center justify-between p-3 border rounded-lg hover:bg-accent/50 transition-colors">
                  <div className="flex-1 min-w-0">
                    <p className="font-mono font-medium text-sm truncate">
                      {scenario.name}
                    </p>
                    {scenario.status && (
                      <div className="flex items-center gap-2 mt-1 flex-wrap">
                        <Badge
                          variant={scenario.status === 'enabled' ? 'default' : 'outline'}
                        >
                          {scenario.status}
                        </Badge>
                        {scenario.version && (
                          <span className="text-xs text-muted-foreground">
                            v{scenario.version}
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                  {scenario.local_path && (
                    <span className="text-xs text-muted-foreground font-mono ml-4 truncate max-w-xs">
                      {scenario.local_path}
                    </span>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <AlertCircle className="h-12 w-12 text-muted-foreground mx-auto mb-2" />
              <p className="text-muted-foreground">No scenarios installed</p>
              {debugInfo && (
                <p className="text-sm text-muted-foreground mt-1">
                  Check the debug info above for more details
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Setup Custom Scenarios */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>Setup Custom Scenarios</CardTitle>
            <CardDescription>
              Add custom detection scenarios to CrowdSec
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {scenarios.map((scenario, index) => (
              <div key={index} className="space-y-4 p-4 border rounded-lg">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold">Scenario {index + 1}</h3>
                  {scenarios.length > 1 && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => handleRemoveScenario(index)}
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor={`name-${index}`}>
                    Scenario Name <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    id={`name-${index}`}
                    type="text"
                    placeholder="e.g., custom/http-bruteforce"
                    value={scenario.name}
                    onChange={(e) => handleScenarioChange(index, 'name', e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    Use format: namespace/scenario-name
                  </p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor={`description-${index}`}>Description</Label>
                  <Input
                    id={`description-${index}`}
                    type="text"
                    placeholder="Brief description of the scenario"
                    value={scenario.description}
                    onChange={(e) => handleScenarioChange(index, 'description', e.target.value)}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor={`content-${index}`}>
                    Scenario Content (YAML) <span className="text-destructive">*</span>
                  </Label>
                  <textarea
                    id={`content-${index}`}
                    className="w-full min-h-[200px] p-3 text-sm font-mono border rounded-md bg-muted/50"
                    placeholder={`type: leaky
name: custom/http-bruteforce
description: Detect HTTP brute force attempts
filter: evt.Meta.log_type == 'http_access-log'
leakspeed: 10s
capacity: 5
groupby: evt.Meta.source_ip
labels:
  service: http
  type: bruteforce
  remediation: true`}
                    value={scenario.content}
                    onChange={(e) => handleScenarioChange(index, 'content', e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    Enter the complete YAML scenario configuration
                  </p>
                </div>
              </div>
            ))}

            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={handleAddScenario}
                className="flex-1"
              >
                <Plus className="mr-2 h-4 w-4" />
                Add Another Scenario
              </Button>
              <Button
                type="submit"
                disabled={setupMutation.isPending}
                className="flex-1"
              >
                {setupMutation.isPending ? 'Setting up...' : 'Setup Scenarios'}
              </Button>
            </div>
          </CardContent>
        </Card>
      </form>

      {/* Example Scenario */}
      <Card>
        <CardHeader>
          <CardTitle>Example Scenario</CardTitle>
          <CardDescription>
            Reference example for creating custom scenarios
          </CardDescription>
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