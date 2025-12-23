import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Button } from '@/components/ui/button'
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  FolderOpen,
  Database,
  Container,
  FileCheck
} from 'lucide-react'
import type { LayerValidation, ValidationCheck, LayerType } from '@/lib/validation-types'
import { useState } from 'react'

interface LayerValidationPanelProps {
  title: string
  layer: LayerType
  validation: LayerValidation
  icon?: React.ReactNode
  className?: string
}

export function LayerValidationPanel({ title, layer, validation, icon, className }: LayerValidationPanelProps) {
  const [expanded, setExpanded] = useState(false)

  const getStatusIcon = () => {
    switch (validation.status) {
      case 'valid':
        return <CheckCircle2 className="h-5 w-5 text-green-500" />
      case 'warning':
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />
      case 'error':
        return <XCircle className="h-5 w-5 text-red-500" />
    }
  }

  const getStatusBadge = () => {
    const variants = {
      valid: 'default',
      warning: 'warning',
      error: 'destructive',
    }
    return (
      <Badge variant={variants[validation.status] as any}>
        {validation.status.toUpperCase()}
      </Badge>
    )
  }

  const getCheckIcon = (check: ValidationCheck) => {
    if (check.valid) {
      return <CheckCircle2 className="h-4 w-4 text-green-500" />
    } else if (check.severity === 'warning') {
      return <AlertTriangle className="h-4 w-4 text-yellow-500" />
    } else {
      return <XCircle className="h-4 w-4 text-red-500" />
    }
  }

  const getLayerIcon = () => {
    switch (layer) {
      case 'host':
        return <FolderOpen className="h-5 w-5" />
      case 'volume':
        return <Database className="h-5 w-5" />
      case 'container':
        return <Container className="h-5 w-5" />
      case 'env':
        return <FileCheck className="h-5 w-5" />
    }
  }

  const totalChecks = validation.checks.length
  const passedChecks = validation.checks.filter(c => c.valid).length
  const progressValue = totalChecks > 0 ? (passedChecks / totalChecks) * 100 : 0

  return (
    <Card className={className}>
      <CardHeader className="cursor-pointer" onClick={() => setExpanded(!expanded)}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {icon || getLayerIcon()}
            <div>
              <CardTitle className="text-lg flex items-center gap-2">
                {title}
                {getStatusIcon()}
                {getStatusBadge()}
              </CardTitle>
              <p className="text-sm text-muted-foreground mt-1">
                {passedChecks} of {totalChecks} checks passed
              </p>
            </div>
          </div>
          <Button variant="ghost" size="sm">
            {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </Button>
        </div>
        <Progress value={progressValue} className="mt-3" />
      </CardHeader>

      {expanded && (
        <CardContent className="space-y-3">
          {validation.checks.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-4">
              No checks to display
            </p>
          ) : (
            validation.checks.map((check, index) => (
              <div
                key={index}
                className={`p-3 rounded-md border ${
                  check.valid
                    ? 'bg-green-50 border-green-200'
                    : check.severity === 'warning'
                    ? 'bg-yellow-50 border-yellow-200'
                    : 'bg-red-50 border-red-200'
                }`}
              >
                <div className="flex items-start gap-3">
                  {getCheckIcon(check)}
                  <div className="flex-1 space-y-1">
                    <div className="flex items-center justify-between">
                      <p className="font-medium text-sm">{check.path}</p>
                      <Badge variant="outline" className="text-xs">
                        {check.type}
                      </Badge>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div>
                        <span className="text-muted-foreground">Exists:</span>{' '}
                        <span className={check.exists ? 'text-green-600' : 'text-red-600'}>
                          {check.exists ? 'Yes' : 'No'}
                        </span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Accessible:</span>{' '}
                        <span className={check.accessible ? 'text-green-600' : 'text-red-600'}>
                          {check.accessible ? 'Yes' : 'No'}
                        </span>
                      </div>
                    </div>

                    {check.expected_location && (
                      <div className="text-xs">
                        <span className="text-muted-foreground">Expected:</span>{' '}
                        <code className="bg-background px-1 rounded">{check.expected_location}</code>
                      </div>
                    )}

                    {check.actual_location && check.actual_location !== check.expected_location && (
                      <div className="text-xs">
                        <span className="text-muted-foreground">Actual:</span>{' '}
                        <code className="bg-background px-1 rounded">{check.actual_location}</code>
                      </div>
                    )}

                    {check.error && (
                      <div className="text-xs text-red-600 bg-red-100 p-2 rounded mt-2">
                        <strong>Error:</strong> {check.error}
                      </div>
                    )}

                    {check.suggestion && (
                      <div className="text-xs text-blue-600 bg-blue-50 p-2 rounded mt-2">
                        <strong>Suggestion:</strong> {check.suggestion}
                      </div>
                    )}

                    {check.details && Object.keys(check.details).length > 0 && (
                      <details className="text-xs mt-2">
                        <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
                          Show details
                        </summary>
                        <div className="mt-2 bg-muted p-2 rounded">
                          {Object.entries(check.details).map(([key, value]) => (
                            <div key={key}>
                              <span className="font-medium">{key}:</span> {value}
                            </div>
                          ))}
                        </div>
                      </details>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </CardContent>
      )}
    </Card>
  )
}
