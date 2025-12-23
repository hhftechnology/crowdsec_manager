import { AnchorHTMLAttributes, ComponentType, ErrorInfo, MouseEvent, ReactNode, useCallback, useEffect, useState } from "react"
import { useNavigate, useLocation, NavigateFunction, Location } from "react-router-dom"
import { ErrorBoundary, ErrorFallbackProps } from "./ErrorBoundary"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { AlertTriangle, Home, ArrowLeft } from "lucide-react"

/**
 * Navigation error fallback component
 */
function NavigationErrorFallback({ error, resetError }: ErrorFallbackProps) {
  return (
    <div className="min-h-[400px] flex items-center justify-center p-4">
      <div className="max-w-md w-full space-y-4">
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Navigation Error</AlertTitle>
          <AlertDescription>
            An error occurred while navigating. The navigation system has been reset.
            {process.env.NODE_ENV === 'development' && error && (
              <details className="mt-2">
                <summary className="cursor-pointer text-sm font-medium">Error Details</summary>
                <pre className="mt-1 text-xs bg-destructive/10 p-2 rounded overflow-auto">
                  {error.message}
                </pre>
              </details>
            )}
          </AlertDescription>
        </Alert>

        <div className="flex gap-2">
          <Button onClick={resetError} className="flex-1">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Try Again
          </Button>
          <Button 
            onClick={() => window.location.href = '/'} 
            variant="outline"
          >
            <Home className="h-4 w-4 mr-2" />
            Go Home
          </Button>
        </div>
      </div>
    </div>
  )
}

/**
 * Safe navigation wrapper with error boundary
 */
export interface SafeNavigationProps {
  children: ReactNode
}

export function SafeNavigation({ children }: SafeNavigationProps) {
  const [navigationKey, setNavigationKey] = useState(0)

  const handleNavigationError = useCallback((error: Error, errorInfo: ErrorInfo) => {
    console.error('Navigation error:', error, errorInfo)
  }, [])

  // const resetNavigation = useCallback(() => {
  //   setNavigationKey(prev => prev + 1)
  // }, []) // Unused function

  return (
    <ErrorBoundary
      key={navigationKey}
      fallback={NavigationErrorFallback}
      onError={handleNavigationError}
      resetKeys={[navigationKey]}
    >
      {children}
    </ErrorBoundary>
  )
}

/**
 * Safe navigation hook with error handling
 */
export function useSafeNavigate() {
  const navigate = useNavigate()
  const [navigationError, setNavigationError] = useState<Error | null>(null)

  const safeNavigate = useCallback<NavigateFunction>(
    (to: any, options?: any) => {
      try {
        setNavigationError(null)
        navigate(to, options)
      } catch (error) {
        console.error('Navigation failed:', error)
        setNavigationError(error as Error)
        
        // Fallback to window.location for critical navigation failures
        if (typeof to === 'string') {
          window.location.href = to
        } else if (typeof to === 'number') {
          window.history.go(to)
        }
      }
    }, 
    [navigate]
  )

  return {
    navigate: safeNavigate, 
    error: navigationError, 
    clearError: () => setNavigationError(null)
  }
}

/**
 * Safe location hook with error handling
 */
export function useSafeLocation() {
  const [locationError, setLocationError] = useState<Error | null>(null)
  
  try {
    const location = useLocation()
    
    if (locationError) {
      setLocationError(null)
    }
    
    return {
      location, 
      error: null, 
      isError: false
    }
  } catch (error) {
    if (!locationError) {
      setLocationError(error as Error)
      console.error('Location error:', error)
    }
    
    // Fallback location object
    return {
      location: {
        pathname: window.location.pathname, 
        search: window.location.search, 
        hash: window.location.hash, 
        state: null, 
        key: 'fallback'
      } as Location, 
      error: error as Error, 
      isError: true
    }
  }
}

/**
 * Navigation guard hook for protected routes
 */
export interface NavigationGuardOptions {
  condition: boolean
  redirectTo?: string
  onBlock?: () => void
  message?: string
}

export function useNavigationGuard({
  condition, 
  redirectTo = '/', 
  onBlock, 
  message = 'Access denied'
}: NavigationGuardOptions) {
  const { navigate } = useSafeNavigate()
  const { location } = useSafeLocation()

  useEffect(() => {
    if (!condition) {
      console.warn(`Navigation blocked: ${message}`)
      onBlock?.()
      
      // Only redirect if not already on the redirect path
      if (location.pathname !== redirectTo) {
        navigate(redirectTo, { replace: true })
      }
    }
  }, [condition, redirectTo, navigate, location.pathname, onBlock, message])

  return condition
}

/**
 * Hook to handle navigation state with error recovery
 */
export function useNavigationState<T = any>(key: string, defaultValue: T) {
  const { location } = useSafeLocation()
  const [state, setState] = useState<T>(() => {
    try {
      const locationState = location.state as any
      return locationState?.[key] ?? defaultValue
    } catch (error) {
      console.error('Failed to read navigation state:', error)
      return defaultValue
    }
  })

  useEffect(() => {
    try {
      const locationState = location.state as any
      if (locationState?.[key] !== undefined) {
        setState(locationState[key])
      }
    } catch (error) {
      console.error('Failed to update navigation state:', error)
    }
  }, [location.state, key])

  return state
}

/**
 * Breadcrumb navigation with error handling
 */
export interface BreadcrumbItem {
  label: string
  path?: string
  icon?: ComponentType<{ className?: string }>
}

export interface SafeBreadcrumbsProps {
  items: BreadcrumbItem[]
  className?: string
}

export function SafeBreadcrumbs({ items, className }: SafeBreadcrumbsProps) {
  const { navigate, error } = useSafeNavigate()

  const handleNavigate = useCallback((path?: string) => {
    if (!path) return
    
    try {
      navigate(path)
    } catch (error) {
      console.error('Breadcrumb navigation failed:', error)
      // Fallback to direct navigation
      window.location.href = path
    }
  }, [navigate])

  if (error) {
    return (
      <div className="text-sm text-muted-foreground">
        Navigation unavailable
      </div>
    )
  }

  return (
    <nav aria-label="Breadcrumb" className={className}>
      <ol className="flex items-center gap-2 text-sm">
        {items.map((item, index) => {
          const isLast = index === items.length - 1
          const Icon = item.icon

          return (
            <li key={index} className="flex items-center gap-2">
              {index > 0 && (
                <span className="text-muted-foreground">/</span>
              )}
              {item.path && !isLast ? (
                <button
                  onClick={() => handleNavigate(item.path)}
                  className="flex items-center gap-1 hover:text-foreground text-muted-foreground transition-colors"
                >
                  {Icon && <Icon className="h-4 w-4" />}
                  {item.label}
                </button>
              ) : (
                <span className="flex items-center gap-1 text-foreground font-medium">
                  {Icon && <Icon className="h-4 w-4" />}
                  {item.label}
                </span>
              )}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}

/**
 * Safe link component with error handling
 */
export interface SafeLinkProps extends AnchorHTMLAttributes<HTMLAnchorElement> {
  to: string
  replace?: boolean
  state?: any
  children: ReactNode
}

export function SafeLink({ to, replace, state, children, onClick, ...props }: SafeLinkProps) {
  const { navigate } = useSafeNavigate()

  const handleClick = useCallback((e: MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault()
    
    onClick?.(e)
    
    if (e.defaultPrevented) return
    
    try {
      navigate(to, { replace, state })
    } catch (error) {
      console.error('Link navigation failed:', error)
      // Fallback to direct navigation
      window.location.href = to
    }
  }, [navigate, to, replace, state, onClick])

  return (
    <a href={to} onClick={handleClick} {...props}>
      {children}
    </a>
  )
}