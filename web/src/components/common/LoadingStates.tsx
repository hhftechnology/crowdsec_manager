import { ReactNode, memo, useCallback, useMemo } from "react"
import { Loader2, RefreshCw, AlertCircle, Wifi, WifiOff } from "lucide-react"
import { cn } from "@/lib/utils"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"

export interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

export const LoadingSpinner = memo(function LoadingSpinner({ size = 'md', className }: LoadingSpinnerProps) {
  const sizeClasses = useMemo(() => ({
    sm: 'h-4 w-4', 
    md: 'h-6 w-6', 
    lg: 'h-8 w-8'
  }), [])

  return (
    <Loader2 className={cn("animate-spin", sizeClasses[size], className)} />
  )
})

export interface SkeletonProps {
  className?: string
}

export const Skeleton = memo(function Skeleton({ className }: SkeletonProps) {
  return (
    <div className={cn("animate-pulse rounded-md bg-muted", className)} />
  )
})

export interface TableSkeletonProps {
  rows?: number
  columns?: number
  className?: string
}

export const TableSkeleton = memo(function TableSkeleton({ rows = 5, columns = 4, className }: TableSkeletonProps) {
  const headerCells = useMemo(() => 
    Array.from({ length: columns }, (_, i) => (
      <div key={i} className="flex-1 px-2">
        <Skeleton className="h-4 w-20" />
      </div>
    )), [columns]
  )

  const tableRows = useMemo(() => 
    Array.from({ length: rows }, (_, rowIndex) => (
      <div key={rowIndex} className="flex items-center h-16 px-4 border-b last:border-b-0">
        {Array.from({ length: columns }, (_, colIndex) => (
          <div key={colIndex} className="flex-1 px-2">
            <Skeleton className="h-4 w-full max-w-32" />
          </div>
        ))}
      </div>
    )), [rows, columns]
  )

  return (
    <div className={cn("space-y-4", className)}>
      {/* Header skeleton */}
      <div className="flex items-center justify-between">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-10 w-32" />
      </div>
      
      {/* Table skeleton */}
      <div className="border rounded-md">
        {/* Table header */}
        <div className="flex items-center h-12 px-4 border-b bg-muted/50">
          {headerCells}
        </div>
        
        {/* Table rows */}
        {tableRows}
      </div>
    </div>
  )
})

export interface CardSkeletonProps {
  className?: string
}

export const CardSkeleton = memo(function CardSkeleton({ className }: CardSkeletonProps) {
  return (
    <Card className={cn("animate-pulse", className)}>
      <CardHeader className="space-y-2">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-8 w-16" />
      </CardHeader>
      <CardContent>
        <Skeleton className="h-3 w-32" />
      </CardContent>
    </Card>
  )
})

export interface GridSkeletonProps {
  items?: number
  columns?: number
  className?: string
}

export const GridSkeleton = memo(function GridSkeleton({ items = 6, columns = 3, className }: GridSkeletonProps) {
  const gridClasses = useMemo(() => cn(
    "grid gap-4", 
    columns === 2 && "grid-cols-1 md:grid-cols-2", 
    columns === 3 && "grid-cols-1 md:grid-cols-2 lg:grid-cols-3", 
    columns === 4 && "grid-cols-1 md:grid-cols-2 lg:grid-cols-4", 
    className
  ), [columns, className])

  const skeletonItems = useMemo(() => 
    Array.from({ length: items }, (_, i) => (
      <CardSkeleton key={i} />
    )), [items]
  )

  return (
    <div className={gridClasses}>
      {skeletonItems}
    </div>
  )
})

export interface LoadingStateProps {
  loading: boolean
  error?: string | Error | null
  onRetry?: () => void
  children: ReactNode
  skeleton?: ReactNode
  className?: string
  loadingText?: string
  retryText?: string
  showErrorDetails?: boolean
}

export const LoadingState = memo(function LoadingState({
  loading, 
  error, 
  onRetry, 
  children, 
  skeleton, 
  className, 
  loadingText = "Loading...", 
  retryText = "Try Again", 
  showErrorDetails = false
}: LoadingStateProps) {
  const errorMessage = useMemo(() => {
    if (!error) return null
    if (typeof error === 'string') return error
    if (error instanceof Error) return error.message
    return 'An unexpected error occurred'
  }, [error])

  const handleRetry = useCallback(() => {
    onRetry?.()
  }, [onRetry])

  if (loading) {
    return (
      <div className={className}>
        {skeleton || (
          <div className="flex flex-col items-center justify-center py-8 space-y-3">
            <LoadingSpinner size="lg" />
            <p className="text-sm text-muted-foreground">{loadingText}</p>
          </div>
        )}
      </div>
    )
  }

  if (error) {
    return (
      <div className={cn("flex flex-col items-center justify-center py-8 text-center space-y-4", className)}>
        <div className="p-3 bg-destructive/10 rounded-full">
          <AlertCircle className="h-8 w-8 text-destructive" />
        </div>
        <div className="space-y-2">
          <p className="text-sm font-medium">Something went wrong</p>
          <p className="text-xs text-muted-foreground">{errorMessage}</p>
          {showErrorDetails && error instanceof Error && error.stack && (
            <Alert variant="destructive" className="text-left max-w-md">
              <AlertDescription className="text-xs font-mono">
                <details>
                  <summary className="cursor-pointer">Error Details</summary>
                  <pre className="mt-2 text-xs overflow-auto max-h-32 p-2 bg-background/50 rounded">
                    {error.stack}
                  </pre>
                </details>
              </AlertDescription>
            </Alert>
          )}
        </div>
        {onRetry && (
          <Button variant="outline" size="sm" onClick={handleRetry}>
            <RefreshCw className="h-4 w-4 mr-2" />
            {retryText}
          </Button>
        )}
      </div>
    )
  }

  return <div className={className}>{children}</div>
})

export interface InlineLoadingProps {
  loading: boolean
  children: ReactNode
  className?: string
}

export const InlineLoading = memo(function InlineLoading({ loading, children, className }: InlineLoadingProps) {
  return (
    <div className={cn("flex items-center gap-2", className)}>
      {loading && <LoadingSpinner size="sm" />}
      {children}
    </div>
  )
})

export interface ButtonLoadingProps {
  loading: boolean
  children: ReactNode
  loadingText?: string
  disabled?: boolean
}

export const ButtonLoading = memo(function ButtonLoading({ loading, children, loadingText }: ButtonLoadingProps) {
  if (loading) {
    return (
      <>
        <LoadingSpinner size="sm" className="mr-2" />
        {loadingText || children}
      </>
    )
  }
  
  return <>{children}</>
})

// Connection status component for real-time features
export interface ConnectionStatusProps {
  isConnected: boolean
  isConnecting?: boolean
  onReconnect?: () => void
  className?: string
  showLabel?: boolean
}

export const ConnectionStatus = memo(function ConnectionStatus({
  isConnected, 
  isConnecting, 
  onReconnect, 
  className, 
  showLabel = true
}: ConnectionStatusProps) {
  const handleReconnect = useCallback(() => {
    onReconnect?.()
  }, [onReconnect])

  if (isConnecting) {
    return (
      <div className={cn("flex items-center gap-2", className)}>
        <LoadingSpinner size="sm" />
        {showLabel && <span className="text-sm text-muted-foreground">Connecting...</span>}
      </div>
    )
  }

  return (
    <div className={cn("flex items-center gap-2", className)}>
      {isConnected ? (
        <>
          <Wifi className="h-4 w-4 text-green-500" />
          {showLabel && (
            <Badge variant="secondary" className="text-green-700 bg-green-100 dark:text-green-300 dark:bg-green-900/30">
              Connected
            </Badge>
          )}
        </>
      ) : (
        <>
          <WifiOff className="h-4 w-4 text-red-500" />
          {showLabel && <Badge variant="destructive">Disconnected</Badge>}
          {onReconnect && (
            <Button onClick={handleReconnect} variant="ghost" size="sm" className="h-6 px-2 ml-2">
              <RefreshCw className="h-3 w-3 mr-1" />
              Reconnect
            </Button>
          )}
        </>
      )}
    </div>
  )
})

// Progressive loading component for multi-step operations
export interface ProgressiveLoadingProps {
  steps: Array<{
    label: string
    status: 'pending' | 'loading' | 'completed' | 'error'
    error?: string
  }>
  className?: string
}

export const ProgressiveLoading = memo(function ProgressiveLoading({ steps, className }: ProgressiveLoadingProps) {
  const stepElements = useMemo(() => 
    steps.map((step, index) => (
      <div key={index} className="flex items-center gap-3">
        <div className="flex-shrink-0">
          {step.status === 'loading' && <LoadingSpinner size="sm" />}
          {step.status === 'completed' && (
            <div className="h-4 w-4 bg-green-500 rounded-full flex items-center justify-center">
              <div className="h-2 w-2 bg-white rounded-full" />
            </div>
          )}
          {step.status === 'error' && (
            <AlertCircle className="h-4 w-4 text-destructive" />
          )}
          {step.status === 'pending' && (
            <div className="h-4 w-4 border-2 border-muted rounded-full" />
          )}
        </div>
        <div className="flex-1">
          <p className={cn(
            "text-sm", 
            step.status === 'completed' && "text-green-600 dark:text-green-400", 
            step.status === 'error' && "text-destructive", 
            step.status === 'loading' && "text-foreground font-medium", 
            step.status === 'pending' && "text-muted-foreground"
          )}>
            {step.label}
          </p>
          {step.error && (
            <p className="text-xs text-destructive mt-1">{step.error}</p>
          )}
        </div>
      </div>
    )), [steps]
  )

  return (
    <div className={cn("space-y-3", className)}>
      {stepElements}
    </div>
  )
})

// Suspense fallback component
export interface SuspenseFallbackProps {
  message?: string
  className?: string
}

export const SuspenseFallback = memo(function SuspenseFallback({ message = "Loading...", className }: SuspenseFallbackProps) {
  return (
    <div 
      className={cn("flex items-center justify-center h-full w-full min-h-[200px]", className)}
      role="status"
      aria-label={message}
    >
      <div className="text-center space-y-3">
        <LoadingSpinner size="lg" />
        <span className="text-sm text-muted-foreground">{message}</span>
      </div>
    </div>
  )
})

// Preset loading components for common patterns
export const LoadingStates = {
  Spinner: LoadingSpinner, 
  Skeleton, 
  TableSkeleton, 
  CardSkeleton, 
  GridSkeleton, 
  LoadingState, 
  InlineLoading, 
  ButtonLoading, 
  ConnectionStatus, 
  ProgressiveLoading, 
  SuspenseFallback
}