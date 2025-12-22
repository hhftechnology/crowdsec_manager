import * as React from "react"
import { 
  AlertTriangle, 
  RefreshCw, 
  Wifi, 
  WifiOff, 
  Server, 
  Database,
  Shield,
  AlertCircle,
  XCircle,
  Clock,
  Loader2
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export interface ErrorStateProps {
  title?: string
  description?: string
  error?: Error | string | null
  onRetry?: () => void
  retryLabel?: string
  showDetails?: boolean
  className?: string
  variant?: 'default' | 'compact' | 'inline'
  type?: 'generic' | 'network' | 'server' | 'database' | 'auth' | 'timeout' | 'validation'
}

const errorTypeConfig = {
  generic: {
    icon: AlertTriangle,
    title: "Something went wrong",
    description: "An unexpected error occurred",
    color: "text-destructive"
  },
  network: {
    icon: WifiOff,
    title: "Connection Error",
    description: "Unable to connect to the server",
    color: "text-orange-500"
  },
  server: {
    icon: Server,
    title: "Server Error",
    description: "The server encountered an error",
    color: "text-red-500"
  },
  database: {
    icon: Database,
    title: "Database Error",
    description: "Unable to access the database",
    color: "text-purple-500"
  },
  auth: {
    icon: Shield,
    title: "Authentication Error",
    description: "You are not authorized to access this resource",
    color: "text-yellow-500"
  },
  timeout: {
    icon: Clock,
    title: "Request Timeout",
    description: "The request took too long to complete",
    color: "text-blue-500"
  },
  validation: {
    icon: XCircle,
    title: "Validation Error",
    description: "The provided data is invalid",
    color: "text-pink-500"
  }
}

/**
 * Comprehensive error state component with different variants and error types
 */
export function ErrorState({
  title,
  description,
  error,
  onRetry,
  retryLabel = "Try Again",
  showDetails = false,
  className,
  variant = 'default',
  type = 'generic'
}: ErrorStateProps) {
  const config = errorTypeConfig[type]
  const Icon = config.icon
  
  const errorMessage = React.useMemo(() => {
    if (typeof error === 'string') return error
    if (error instanceof Error) return error.message
    return null
  }, [error])

  const finalTitle = title || config.title
  const finalDescription = description || errorMessage || config.description

  if (variant === 'inline') {
    return (
      <div className={cn("flex items-center gap-2 text-sm p-2 rounded-md bg-destructive/10", className)}>
        <Icon className={cn("h-4 w-4 flex-shrink-0", config.color)} />
        <span className="flex-1 text-destructive">{finalTitle}</span>
        {onRetry && (
          <Button onClick={onRetry} variant="ghost" size="sm" className="h-6 px-2">
            <RefreshCw className="h-3 w-3 mr-1" />
            {retryLabel}
          </Button>
        )}
      </div>
    )
  }

  if (variant === 'compact') {
    return (
      <Alert variant="destructive" className={cn("my-4", className)}>
        <Icon className="h-4 w-4" />
        <AlertTitle>{finalTitle}</AlertTitle>
        <AlertDescription className="flex items-center justify-between">
          <span className="text-sm">{finalDescription}</span>
          {onRetry && (
            <Button onClick={onRetry} variant="outline" size="sm">
              <RefreshCw className="h-3 w-3 mr-1" />
              {retryLabel}
            </Button>
          )}
        </AlertDescription>
      </Alert>
    )
  }

  return (
    <div className={cn("flex items-center justify-center p-8", className)}>
      <Card className="w-full max-w-md text-center">
        <CardHeader>
          <div className="mx-auto mb-4 p-3 bg-destructive/10 rounded-full w-fit">
            <Icon className={cn("h-8 w-8", config.color)} />
          </div>
          <CardTitle className="text-lg">{finalTitle}</CardTitle>
          <CardDescription>{finalDescription}</CardDescription>
        </CardHeader>
        
        {(showDetails && error instanceof Error) && (
          <CardContent className="pt-0">
            <Alert variant="destructive" className="text-left">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle className="text-sm">Error Details</AlertTitle>
              <AlertDescription className="text-xs font-mono mt-2">
                {error.name}: {error.message}
                {error.stack && (
                  <pre className="mt-2 text-xs overflow-auto max-h-32 p-2 bg-background/50 rounded">
                    {error.stack}
                  </pre>
                )}
              </AlertDescription>
            </Alert>
          </CardContent>
        )}
        
        {onRetry && (
          <CardContent className={showDetails ? "pt-4" : ""}>
            <Button onClick={onRetry} className="w-full">
              <RefreshCw className="h-4 w-4 mr-2" />
              {retryLabel}
            </Button>
          </CardContent>
        )}
      </Card>
    </div>
  )
}

/**
 * Network-specific error state
 */
export function NetworkErrorState({ onRetry, className, ...props }: Omit<ErrorStateProps, 'type'>) {
  return (
    <ErrorState
      type="network"
      onRetry={onRetry}
      className={className}
      {...props}
    />
  )
}

/**
 * Server error state
 */
export function ServerErrorState({ onRetry, className, ...props }: Omit<ErrorStateProps, 'type'>) {
  return (
    <ErrorState
      type="server"
      onRetry={onRetry}
      className={className}
      {...props}
    />
  )
}

/**
 * Authentication error state
 */
export function AuthErrorState({ onRetry, className, ...props }: Omit<ErrorStateProps, 'type'>) {
  return (
    <ErrorState
      type="auth"
      onRetry={onRetry}
      className={className}
      {...props}
    />
  )
}

/**
 * Data loading error state with retry functionality
 */
export interface DataErrorStateProps extends ErrorStateProps {
  isLoading?: boolean
  isEmpty?: boolean
  emptyMessage?: string
  emptyDescription?: string
}

export function DataErrorState({
  isLoading,
  isEmpty,
  emptyMessage = "No data available",
  emptyDescription = "There's nothing to display right now",
  ...props
}: DataErrorStateProps) {
  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">Loading...</p>
        </div>
      </div>
    )
  }

  if (isEmpty) {
    return (
      <div className="flex items-center justify-center p-8">
        <Card className="w-full max-w-md text-center">
          <CardHeader>
            <div className="mx-auto mb-4 p-3 bg-muted rounded-full w-fit">
              <Database className="h-8 w-8 text-muted-foreground" />
            </div>
            <CardTitle className="text-lg">{emptyMessage}</CardTitle>
            <CardDescription>{emptyDescription}</CardDescription>
          </CardHeader>
          {props.onRetry && (
            <CardContent>
              <Button onClick={props.onRetry} variant="outline">
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </CardContent>
          )}
        </Card>
      </div>
    )
  }

  return <ErrorState {...props} />
}

/**
 * Connection status indicator
 */
export interface ConnectionStatusProps {
  isConnected: boolean
  isConnecting?: boolean
  onReconnect?: () => void
  className?: string
}

export function ConnectionStatus({
  isConnected,
  isConnecting,
  onReconnect,
  className
}: ConnectionStatusProps) {
  if (isConnecting) {
    return (
      <div className={cn("flex items-center gap-2 text-sm text-muted-foreground", className)}>
        <Loader2 className="h-4 w-4 animate-spin" />
        <span>Connecting...</span>
      </div>
    )
  }

  return (
    <div className={cn("flex items-center gap-2 text-sm", className)}>
      {isConnected ? (
        <>
          <Wifi className="h-4 w-4 text-green-500" />
          <Badge variant="secondary" className="text-green-700 bg-green-100 dark:text-green-300 dark:bg-green-900/30">
            Connected
          </Badge>
        </>
      ) : (
        <>
          <WifiOff className="h-4 w-4 text-red-500" />
          <Badge variant="destructive">
            Disconnected
          </Badge>
          {onReconnect && (
            <Button onClick={onReconnect} variant="ghost" size="sm" className="h-6 px-2 ml-2">
              <RefreshCw className="h-3 w-3 mr-1" />
              Reconnect
            </Button>
          )}
        </>
      )}
    </div>
  )
}

/**
 * Error boundary fallback specifically for data loading errors
 */
export function DataLoadingErrorFallback({ error, resetError }: { error: Error | null; resetError: () => void }) {
  return (
    <DataErrorState
      error={error}
      onRetry={resetError}
      showDetails={process.env.NODE_ENV === 'development'}
    />
  )
}

/**
 * Hook to handle common error states
 */
export function useErrorState() {
  const [error, setError] = React.useState<Error | null>(null)
  const [isRetrying, setIsRetrying] = React.useState(false)

  const handleError = React.useCallback((error: Error | string) => {
    setError(error instanceof Error ? error : new Error(error))
  }, [])

  const clearError = React.useCallback(() => {
    setError(null)
    setIsRetrying(false)
  }, [])

  const retry = React.useCallback(async (retryFn?: () => Promise<void> | void) => {
    if (!retryFn) {
      clearError()
      return
    }

    setIsRetrying(true)
    try {
      await retryFn()
      clearError()
    } catch (error) {
      handleError(error as Error)
    } finally {
      setIsRetrying(false)
    }
  }, [clearError, handleError])

  return {
    error,
    isRetrying,
    handleError,
    clearError,
    retry
  }
}