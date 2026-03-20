import { useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'

export interface QueryErrorProps {
  error: Error | null
  onRetry?: () => void
}

export function QueryError({ error, onRetry }: QueryErrorProps) {
  const [showDetails, setShowDetails] = useState(false)
  if (!error) return null
  return (
    <Card className="border-destructive">
      <CardContent className="flex items-center gap-4 p-6">
        <AlertTriangle className="h-8 w-8 text-destructive shrink-0" />
        <div className="flex-1">
          <p className="font-medium">Something went wrong</p>
          <p className="text-sm text-muted-foreground mt-1">{error.message}</p>
          {showDetails && (
            <pre className="mt-3 max-h-40 overflow-auto rounded bg-muted p-3 text-xs text-muted-foreground">
              {error.stack || error.message}
            </pre>
          )}
          <div className="mt-3 flex items-center gap-3">
            <Button variant="link" size="sm" onClick={() => setShowDetails((prev) => !prev)}>
              {showDetails ? 'Hide details' : 'Show details'}
            </Button>
            <Button variant="link" size="sm" asChild>
              <a href="/logs">Open logs</a>
            </Button>
          </div>
        </div>
        {onRetry && (
          <Button variant="outline" size="sm" onClick={onRetry}>
            Retry
          </Button>
        )}
      </CardContent>
    </Card>
  )
}
