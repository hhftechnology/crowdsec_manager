import * as React from "react"
import { notifications } from "@/components/common/NotificationComponents"

export interface ErrorInfo {
  id: string
  error: Error
  context?: string
  timestamp: Date
  recovered?: boolean
}

export interface ErrorContextType {
  errors: ErrorInfo[]
  reportError: (error: Error, context?: string) => string
  clearError: (id: string) => void
  clearAllErrors: () => void
  markRecovered: (id: string) => void
  getErrorsByContext: (context: string) => ErrorInfo[]
  hasErrors: boolean
  hasUnrecoveredErrors: boolean
}

const ErrorContext = React.createContext<ErrorContextType | undefined>(undefined)

export interface ErrorProviderProps {
  children: React.ReactNode
  maxErrors?: number
  autoNotify?: boolean
}

export function ErrorProvider({ 
  children, 
  maxErrors = 50,
  autoNotify = true 
}: ErrorProviderProps) {
  const [errors, setErrors] = React.useState<ErrorInfo[]>([])

  const reportError = React.useCallback((error: Error, context?: string): string => {
    const errorInfo: ErrorInfo = {
      id: `error-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      error,
      context,
      timestamp: new Date(),
      recovered: false
    }

    setErrors(prev => {
      const newErrors = [errorInfo, ...prev]
      // Keep only the most recent errors
      return newErrors.slice(0, maxErrors)
    })

    // Auto-notify if enabled
    if (autoNotify) {
      notifications.error(
        error.message || 'An error occurred',
        context ? `Context: ${context}` : undefined
      )
    }

    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.error(`Error in ${context || 'unknown context'}:`, error)
    }

    return errorInfo.id
  }, [maxErrors, autoNotify])

  const clearError = React.useCallback((id: string) => {
    setErrors(prev => prev.filter(error => error.id !== id))
  }, [])

  const clearAllErrors = React.useCallback(() => {
    setErrors([])
  }, [])

  const markRecovered = React.useCallback((id: string) => {
    setErrors(prev => prev.map(error => 
      error.id === id ? { ...error, recovered: true } : error
    ))
  }, [])

  const getErrorsByContext = React.useCallback((context: string) => {
    return errors.filter(error => error.context === context)
  }, [errors])

  const hasErrors = errors.length > 0
  const hasUnrecoveredErrors = errors.some(error => !error.recovered)

  const contextValue: ErrorContextType = {
    errors,
    reportError,
    clearError,
    clearAllErrors,
    markRecovered,
    getErrorsByContext,
    hasErrors,
    hasUnrecoveredErrors
  }

  return (
    <ErrorContext.Provider value={contextValue}>
      {children}
    </ErrorContext.Provider>
  )
}

export function useErrorReporting() {
  const context = React.useContext(ErrorContext)
  if (context === undefined) {
    throw new Error('useErrorReporting must be used within an ErrorProvider')
  }
  return context
}

/**
 * Hook to handle errors in a specific context
 */
export function useContextualErrorHandler(context: string) {
  const { reportError, clearError, getErrorsByContext, markRecovered } = useErrorReporting()

  const handleError = React.useCallback((error: Error) => {
    return reportError(error, context)
  }, [reportError, context])

  const clearContextErrors = React.useCallback(() => {
    const contextErrors = getErrorsByContext(context)
    contextErrors.forEach(error => clearError(error.id))
  }, [getErrorsByContext, clearError, context])

  const contextErrors = getErrorsByContext(context)
  const hasContextErrors = contextErrors.length > 0

  return {
    handleError,
    clearContextErrors,
    markRecovered,
    contextErrors,
    hasContextErrors
  }
}

/**
 * Hook to wrap async operations with error handling
 */
export function useAsyncErrorHandler<T extends (...args: any[]) => Promise<any>>(
  asyncFn: T,
  context?: string
): T {
  const { reportError } = useErrorReporting()

  return React.useCallback(async (...args: Parameters<T>) => {
    try {
      return await asyncFn(...args)
    } catch (error) {
      const errorId = reportError(
        error instanceof Error ? error : new Error(String(error)),
        context
      )
      throw { ...error, errorId }
    }
  }, [asyncFn, reportError, context]) as T
}

/**
 * Higher-order component to wrap components with error reporting
 */
export function withErrorReporting<P extends object>(
  Component: React.ComponentType<P>,
  context?: string
) {
  const WrappedComponent = (props: P) => {
    const { reportError } = useErrorReporting()

    React.useEffect(() => {
      const handleError = (event: ErrorEvent) => {
        reportError(
          new Error(event.message),
          context || Component.displayName || Component.name
        )
      }

      const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
        reportError(
          event.reason instanceof Error ? event.reason : new Error(String(event.reason)),
          context || Component.displayName || Component.name
        )
      }

      window.addEventListener('error', handleError)
      window.addEventListener('unhandledrejection', handleUnhandledRejection)

      return () => {
        window.removeEventListener('error', handleError)
        window.removeEventListener('unhandledrejection', handleUnhandledRejection)
      }
    }, [reportError])

    return <Component {...props} />
  }

  WrappedComponent.displayName = `withErrorReporting(${Component.displayName || Component.name})`

  return WrappedComponent
}