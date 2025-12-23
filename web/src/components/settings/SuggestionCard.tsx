import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  AlertTriangle,
  Info,
  XCircle,
  Copy,
  Check,
  FileText,
  Folder,
  Database,
  Terminal
} from 'lucide-react'
import type { Suggestion } from '@/lib/validation-types'
import { toast } from 'sonner'

interface SuggestionCardProps {
  suggestion: Suggestion
  onApply?: (suggestion: Suggestion) => void
  className?: string
}

export function SuggestionCard({ suggestion, onApply, className }: SuggestionCardProps) {
  const [copied, setCopied] = useState(false)

  const getSeverityIcon = () => {
    switch (suggestion.severity) {
      case 'error':
        return <XCircle className="h-5 w-5 text-red-500" />
      case 'warning':
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />
      case 'info':
        return <Info className="h-5 w-5 text-blue-500" />
    }
  }

  const getSeverityColor = () => {
    switch (suggestion.severity) {
      case 'error':
        return 'destructive'
      case 'warning':
        return 'warning'
      case 'info':
        return 'secondary'
    }
  }

  const getTypeIcon = () => {
    switch (suggestion.type) {
      case 'create_file':
        return <FileText className="h-4 w-4" />
      case 'create_directory':
        return <Folder className="h-4 w-4" />
      case 'update_env':
        return <Database className="h-4 w-4" />
      case 'add_volume':
        return <Terminal className="h-4 w-4" />
      default:
        return <Terminal className="h-4 w-4" />
    }
  }

  const handleCopy = () => {
    if (suggestion.command) {
      navigator.clipboard.writeText(suggestion.command)
      setCopied(true)
      toast.success('Command copied to clipboard')
      setTimeout(() => setCopied(false), 2000)
    } else if (suggestion.env_update) {
      const envLine = `${suggestion.env_update.key}=${suggestion.env_update.suggested_value}`
      navigator.clipboard.writeText(envLine)
      setCopied(true)
      toast.success('Environment variable copied')
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const handleApply = () => {
    if (onApply) {
      onApply(suggestion)
      toast.success('Applied suggestion')
    }
  }

  return (
    <Card className={className}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            {getSeverityIcon()}
            <div className="space-y-1">
              <CardTitle className="text-base flex items-center gap-2">
                {suggestion.title}
                <Badge variant={getSeverityColor() as any} className="ml-2">
                  {suggestion.severity}
                </Badge>
                {getTypeIcon()}
              </CardTitle>
              <CardDescription>{suggestion.message}</CardDescription>
            </div>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Impact */}
        {suggestion.impact && (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              <strong>Impact:</strong> {suggestion.impact}
            </AlertDescription>
          </Alert>
        )}

        {/* Environment Variable Update */}
        {suggestion.env_update && (
          <div className="space-y-2">
            <p className="text-sm font-medium">Environment Variable Update:</p>
            <div className="bg-muted p-3 rounded-md font-mono text-sm space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Variable:</span>
                <code>{suggestion.env_update.key}</code>
              </div>
              {suggestion.env_update.current_value && (
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Current:</span>
                  <code className="text-red-500">{suggestion.env_update.current_value}</code>
                </div>
              )}
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Suggested:</span>
                <code className="text-green-500">{suggestion.env_update.suggested_value}</code>
              </div>
            </div>
            <p className="text-xs text-muted-foreground">{suggestion.env_update.reason}</p>
          </div>
        )}

        {/* Volume Update */}
        {suggestion.volume_update && (
          <div className="space-y-2">
            <p className="text-sm font-medium">Volume Mapping:</p>
            <div className="bg-muted p-3 rounded-md font-mono text-sm">
              <code>
                {suggestion.volume_update.host_path}:{suggestion.volume_update.container_path}:
                {suggestion.volume_update.mode}
              </code>
            </div>
            <p className="text-xs text-muted-foreground">{suggestion.volume_update.reason}</p>
          </div>
        )}

        {/* File Create */}
        {suggestion.file_create && (
          <div className="space-y-2">
            <p className="text-sm font-medium">Create {suggestion.file_create.type}:</p>
            <div className="bg-muted p-3 rounded-md font-mono text-sm">
              <code>{suggestion.file_create.path}</code>
            </div>
            <p className="text-xs text-muted-foreground">{suggestion.file_create.reason}</p>
          </div>
        )}

        {/* Command */}
        {suggestion.command && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium">Command:</p>
              <Button
                variant="ghost"
                size="sm"
                onClick={handleCopy}
                className="h-7"
              >
                {copied ? (
                  <>
                    <Check className="h-3 w-3 mr-1" />
                    Copied
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3 mr-1" />
                    Copy
                  </>
                )}
              </Button>
            </div>
            <div className="bg-black text-green-400 p-3 rounded-md font-mono text-xs overflow-x-auto">
              <pre className="whitespace-pre-wrap">{suggestion.command}</pre>
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-2 pt-2">
          {suggestion.auto_fixable && onApply && (
            <Button onClick={handleApply} size="sm">
              Apply Suggestion
            </Button>
          )}
          {!suggestion.command && suggestion.env_update && (
            <Button onClick={handleCopy} size="sm" variant="outline">
              <Copy className="h-3 w-3 mr-1" />
              Copy Env Var
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
