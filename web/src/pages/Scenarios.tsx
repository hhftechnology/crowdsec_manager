import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { Scenario, ScenarioSetupRequest } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { FileText, Plus, X } from 'lucide-react'

export default function Scenarios() {
  const queryClient = useQueryClient()
  const [scenarios, setScenarios] = useState<Scenario[]>([
    { name: '', description: '', content: '' }
  ])

  const { data: scenariosList, isLoading } = useQuery({
    queryKey: ['scenarios'],
    queryFn: async () => {
      const response = await api.scenarios.list()
      return response.data.data
    },
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

  const parseScenariosList = (scenariosStr: string | undefined): string[] => {
    if (!scenariosStr) return []
    const lines = scenariosStr.split('\n').filter(line => line.trim() && !line.includes('─') && !line.includes('NAME'))
    return lines.map(line => {
      const parts = line.split(/\s+/).filter(p => p && p !== '│')
      return parts[0] || ''
    }).filter(name => name && name !== 'NAME')
  }

  const scenarioNames = parseScenariosList(scenariosList?.scenarios)

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
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Active Scenarios
          </CardTitle>
          <CardDescription>
            Currently installed CrowdSec scenarios
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-2">
              <div className="h-12 bg-muted animate-pulse rounded" />
              <div className="h-12 bg-muted animate-pulse rounded" />
            </div>
          ) : scenarioNames.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {scenarioNames.map((name, index) => (
                <Badge key={index} variant="secondary" className="font-mono">
                  {name}
                </Badge>
              ))}
            </div>
          ) : (
            <p className="text-muted-foreground text-center py-8">
              No custom scenarios installed
            </p>
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
