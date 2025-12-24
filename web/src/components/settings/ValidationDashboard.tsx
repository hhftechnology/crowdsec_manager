import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Download,
  Lightbulb,
  FolderOpen,
  Database,
  Container,
  FileText
} from 'lucide-react'
import api from '@/lib/api'
import { LayerValidationPanel } from './LayerValidationPanel'
import { SuggestionCard } from './SuggestionCard'
import { toast } from 'sonner'
import type { ValidationResult, Suggestion } from '@/lib/validation-types'

interface ValidationDashboardProps {
  className?: string
}

export function ValidationDashboard({ className }: ValidationDashboardProps) {
  const [isValidating, setIsValidating] = useState(false)

  const {
    data: validationData,
    isLoading,
    error,
    refetch
  } = useQuery({
    queryKey: ['validation-complete'],
    queryFn: async () => {
      const response = await api.validation.validateComplete()
      return response.data.data as ValidationResult
    },
    staleTime: 30000, // 30 seconds
  })

  const handleValidate = async () => {
    setIsValidating(true)
    try {
      await refetch()
      toast.success('Validation completed')
    } catch (err) {
      toast.error('Validation failed')
    } finally {
      setIsValidating(false)
    }
  }

  const handleExportEnv = async () => {
    try {
      const response = await api.validation.exportEnvFile()
      const blob = new Blob([response.data], { type: 'text/plain' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = '.env'
      a.click()
      window.URL.revokeObjectURL(url)
      toast.success('Environment file downloaded')
    } catch (err) {
      toast.error('Failed to export environment file')
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'valid':
        return <CheckCircle2 className="h-6 w-6 text-green-500" />
      case 'warning':
        return <AlertTriangle className="h-6 w-6 text-yellow-500" />
      case 'error':
        return <XCircle className="h-6 w-6 text-red-500" />
    }
  }

  if (isLoading) {
    return (
      <Card className={className}>
        <CardContent className="py-8">
          <div className="flex items-center justify-center">
            <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        </CardContent>
      </Card>
    )
  }

  if (error) {
    console.error('Validation Dashboard Error:', error)
    return (
      <Card className={className}>
        <CardContent className="py-8">
          <Alert variant="destructive">
            <AlertDescription>
              Failed to load validation data. {(error as any)?.message || 'Unknown error'}
            </AlertDescription>

          </Alert>
          <Button onClick={handleValidate} className="mt-4">
            <RefreshCw className="h-4 w-4 mr-2" />
            Retry
          </Button>
        </CardContent>
      </Card>
    )
  }

  if (!validationData) {
    return null
  }

  const { summary, layers, suggestions, env_vars, proxy_type } = validationData
  const errorSuggestions = suggestions.filter(s => s.severity === 'error')
  const warningSuggestions = suggestions.filter(s => s.severity === 'warning')
  const infoSuggestions = suggestions.filter(s => s.severity === 'info')

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold">Configuration Validation</h2>
          <p className="text-muted-foreground mt-1">
            Validate environment variables, paths, and Docker volumes for {proxy_type} proxy
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button onClick={handleExportEnv} variant="outline">
            <Download className="h-4 w-4 mr-2" />
            Export .env
          </Button>
          <Button onClick={handleValidate} disabled={isValidating}>
            {isValidating ? (
              <>
                <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                Validating...
              </>
            ) : (
              <>
                <RefreshCw className="h-4 w-4 mr-2" />
                Re-validate
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Summary Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {getStatusIcon(summary.overall_status)}
              <div>
                <CardTitle>Validation Summary</CardTitle>
                <CardDescription>
                  Last validated: {new Date(validationData.timestamp).toLocaleString()}
                </CardDescription>
              </div>
            </div>
            <Badge
              variant={summary.overall_status === 'error' ? 'destructive' : summary.overall_status === 'warning' ? 'warning' as any : 'default'}
              className="text-lg px-4 py-2"
            >
              {summary.overall_status.toUpperCase()}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-muted p-4 rounded-lg">
              <p className="text-sm text-muted-foreground">Total Checks</p>
              <p className="text-2xl font-bold">{summary.total_checks}</p>
            </div>
            <div className="bg-green-50 border border-green-200 p-4 rounded-lg">
              <p className="text-sm text-green-700">Passed</p>
              <p className="text-2xl font-bold text-green-700">{summary.passed_checks}</p>
            </div>
            <div className="bg-yellow-50 border border-yellow-200 p-4 rounded-lg">
              <p className="text-sm text-yellow-700">Warnings</p>
              <p className="text-2xl font-bold text-yellow-700">{summary.warning_checks}</p>
            </div>
            <div className="bg-red-50 border border-red-200 p-4 rounded-lg">
              <p className="text-sm text-red-700">Failed</p>
              <p className="text-2xl font-bold text-red-700">{summary.failed_checks}</p>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span>Overall Progress</span>
              <span className="font-medium">
                {summary.passed_checks} / {summary.total_checks}
              </span>
            </div>
            <Progress value={(summary.passed_checks / summary.total_checks) * 100} />
          </div>

          <Alert variant={summary.ready_to_deploy ? 'default' : 'destructive'}>
            <AlertDescription className="flex items-center gap-2">
              {summary.ready_to_deploy ? (
                <>
                  <CheckCircle2 className="h-4 w-4" />
                  Configuration is ready for deployment
                </>
              ) : (
                <>
                  <XCircle className="h-4 w-4" />
                  Configuration has critical issues that must be fixed before deployment
                </>
              )}
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>

      {/* Tabs for different views */}
      <Tabs defaultValue="layers" className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="layers">
            <Container className="h-4 w-4 mr-2" />
            Layer Validation
          </TabsTrigger>
          <TabsTrigger value="suggestions">
            <Lightbulb className="h-4 w-4 mr-2" />
            Suggestions ({suggestions.length})
          </TabsTrigger>
          <TabsTrigger value="env">
            <FileText className="h-4 w-4 mr-2" />
            Environment Variables
          </TabsTrigger>
        </TabsList>

        {/* Layer Validation Tab */}
        <TabsContent value="layers" className="space-y-4">
          <LayerValidationPanel
            title="Host Paths"
            layer="host"
            validation={layers.host_paths}
            icon={<FolderOpen className="h-5 w-5" />}
          />
          <LayerValidationPanel
            title="Volume Mappings"
            layer="volume"
            validation={layers.volume_mappings}
            icon={<Database className="h-5 w-5" />}
          />
          <LayerValidationPanel
            title="Container Paths"
            layer="container"
            validation={layers.container_paths}
            icon={<Container className="h-5 w-5" />}
          />
        </TabsContent>

        {/* Suggestions Tab */}
        <TabsContent value="suggestions" className="space-y-4">
          {suggestions.length === 0 ? (
            <Card>
              <CardContent className="py-8 text-center">
                <CheckCircle2 className="h-12 w-12 text-green-500 mx-auto mb-4" />
                <p className="text-lg font-medium">No suggestions</p>
                <p className="text-muted-foreground">
                  Your configuration looks good!
                </p>
              </CardContent>
            </Card>
          ) : (
            <>
              {errorSuggestions.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-lg font-semibold flex items-center gap-2">
                    <XCircle className="h-5 w-5 text-red-500" />
                    Critical Issues ({errorSuggestions.length})
                  </h3>
                  {errorSuggestions.map((suggestion) => (
                    <SuggestionCard key={suggestion.id} suggestion={suggestion} />
                  ))}
                </div>
              )}

              {warningSuggestions.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-lg font-semibold flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-yellow-500" />
                    Warnings ({warningSuggestions.length})
                  </h3>
                  {warningSuggestions.map((suggestion) => (
                    <SuggestionCard key={suggestion.id} suggestion={suggestion} />
                  ))}
                </div>
              )}

              {infoSuggestions.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-lg font-semibold flex items-center gap-2">
                    <Lightbulb className="h-5 w-5 text-blue-500" />
                    Optimizations ({infoSuggestions.length})
                  </h3>
                  {infoSuggestions.map((suggestion) => (
                    <SuggestionCard key={suggestion.id} suggestion={suggestion} />
                  ))}
                </div>
              )}
            </>
          )}
        </TabsContent>

        {/* Environment Variables Tab */}
        <TabsContent value="env" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Required Environment Variables</CardTitle>
              <CardDescription>
                These variables are required for {proxy_type} proxy to function
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {env_vars.required.map((envVar) => (
                  <div
                    key={envVar.name}
                    className={`p-3 rounded-md border ${
                      envVar.valid
                        ? 'bg-green-50 border-green-200'
                        : 'bg-red-50 border-red-200'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {envVar.valid ? (
                          <CheckCircle2 className="h-4 w-4 text-green-500" />
                        ) : (
                          <XCircle className="h-4 w-4 text-red-500" />
                        )}
                        <code className="font-mono text-sm font-medium">{envVar.name}</code>
                      </div>
                      <Badge variant={envVar.set ? 'default' : 'destructive'}>
                        {envVar.set ? 'Set' : 'Not Set'}
                      </Badge>
                    </div>
                    {envVar.set && envVar.value && (
                      <div className="mt-2 text-sm">
                        <span className="text-muted-foreground">Value:</span>{' '}
                        <code className="bg-background px-1 rounded">{envVar.value}</code>
                      </div>
                    )}
                    <p className="text-xs text-muted-foreground mt-2">{envVar.description}</p>
                    {envVar.error && (
                      <p className="text-xs text-red-600 mt-2">{envVar.error}</p>
                    )}
                    {envVar.suggestion && (
                      <p className="text-xs text-blue-600 mt-2">{envVar.suggestion}</p>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {env_vars.optional.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Optional Environment Variables</CardTitle>
                <CardDescription>
                  These variables enable additional features
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {env_vars.optional.map((envVar) => (
                    <div
                      key={envVar.name}
                      className="p-3 rounded-md border bg-muted"
                    >
                      <div className="flex items-center justify-between">
                        <code className="font-mono text-sm font-medium">{envVar.name}</code>
                        <Badge variant={envVar.set ? 'default' : 'secondary'}>
                          {envVar.set ? 'Set' : 'Not Set'}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mt-2">{envVar.description}</p>
                      {envVar.impact && !envVar.set && (
                        <p className="text-xs text-yellow-600 mt-2">Impact: {envVar.impact}</p>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}
