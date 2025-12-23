import { ComponentType, ErrorInfo, ReactNode, useCallback, useEffect, useState } from "react"
import { ThemeProvider, useTheme } from "@/components/ThemeProvider"
import { ErrorBoundary, ErrorFallbackProps } from "./ErrorBoundary"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { AlertTriangle, RefreshCw, Palette } from "lucide-react"

/**
 * Theme error fallback component
 */
function ThemeErrorFallback({ error, resetError }: ErrorFallbackProps) {
  // Apply basic fallback theme directly to avoid theme context issues
  useEffect(() => {
    document.documentElement.classList.remove('dark', 'light')
    document.documentElement.classList.add('light')
    document.documentElement.style.colorScheme = 'light'
  }, [])

  return (
    <div className="min-h-screen bg-white text-black p-4 flex items-center justify-center">
      <div className="max-w-md w-full space-y-4">
        <Alert className="border-red-200 bg-red-50">
          <AlertTriangle className="h-4 w-4 text-red-600" />
          <AlertTitle className="text-red-800">Theme System Error</AlertTitle>
          <AlertDescription className="text-red-700">
            The theme system encountered an error and has been reset to light mode.
            {process.env.NODE_ENV === 'development' && error && (
              <details className="mt-2">
                <summary className="cursor-pointer text-sm font-medium">Error Details</summary>
                <pre className="mt-1 text-xs bg-red-100 p-2 rounded overflow-auto">
                  {error.message}
                </pre>
              </details>
            )}
          </AlertDescription>
        </Alert>

        <div className="flex gap-2">
          <Button onClick={resetError} className="flex-1">
            <RefreshCw className="h-4 w-4 mr-2" />
            Restore Theme System
          </Button>
          <Button 
            onClick={() => window.location.reload()} 
            variant="outline"
          >
            <Palette className="h-4 w-4 mr-2" />
            Reload Page
          </Button>
        </div>

        <p className="text-sm text-gray-600 text-center">
          The application will continue to work in light mode until the theme system is restored.
        </p>
      </div>
    </div>
  )
}

/**
 * Safe theme provider with error boundary and fallback handling
 */
export interface SafeThemeProviderProps {
  children: ReactNode
  defaultTheme?: 'light' | 'dark' | 'system'
  enableSystemDetection?: boolean
  enableAccessibilityFeatures?: boolean
}

export function SafeThemeProvider({
  children, 
  defaultTheme = 'system', 
  enableSystemDetection = true, 
  enableAccessibilityFeatures = true
}: SafeThemeProviderProps) {
  const [themeKey, setThemeKey] = useState(0)

  const handleThemeError = useCallback((error: Error, errorInfo: ErrorInfo) => {
    console.error('Theme system error:', error, errorInfo)
    
    // Apply emergency fallback theme
    try {
      document.documentElement.classList.remove('dark', 'light')
      document.documentElement.classList.add('light')
      document.documentElement.style.colorScheme = 'light'
      
      // Clear potentially corrupted theme data
      localStorage.removeItem('theme')
      localStorage.removeItem('accessibility-preferences')
    } catch (fallbackError) {
      console.error('Failed to apply emergency theme fallback:', fallbackError)
    }
  }, [])

  // const resetTheme = useCallback(() => {
  //   // Force re-mount of theme provider
  //   setThemeKey(prev => prev + 1)
  // }, []) // Unused function

  return (
    <ErrorBoundary
      key={themeKey}
      fallback={ThemeErrorFallback}
      onError={handleThemeError}
      resetKeys={[themeKey]}
    >
      <ThemeProvider
        defaultTheme={defaultTheme}
        enableSystemDetection={enableSystemDetection}
        enableAccessibilityFeatures={enableAccessibilityFeatures}
      >
        {children}
      </ThemeProvider>
    </ErrorBoundary>
  )
}

/**
 * Hook to safely access theme with error handling
 */
export function useSafeTheme() {
  const [themeError, setThemeError] = useState<Error | null>(null)
  
  try {
    const theme = useTheme()
    
    // Clear any previous errors if theme is working
    if (themeError) {
      setThemeError(null)
    }
    
    return {
      ...theme, 
      error: null, 
      isError: false
    }
  } catch (error) {
    // Fallback theme state when theme context fails
    const fallbackTheme = {
      theme: 'light' as const, 
      resolvedTheme: 'light' as const, 
      systemTheme: 'light' as const, 
      accessibility: {
        highContrast: false, 
        reducedMotion: false, 
        largeText: false, 
        screenReaderOptimized: false, 
      }, 
      setTheme: () => {
        console.warn('Theme system is in error state, cannot change theme')
      }, 
      setAccessibilityPreference: () => {
        console.warn('Theme system is in error state, cannot change accessibility preferences')
      }, 
      toggleAccessibilityPreference: () => {
        console.warn('Theme system is in error state, cannot toggle accessibility preferences')
      }, 
      error: error as Error, 
      isError: true
    }

    // Store error for debugging
    if (!themeError) {
      setThemeError(error as Error)
      console.error('Theme context error:', error)
    }

    return fallbackTheme
  }
}

/**
 * Theme-aware component wrapper that handles theme errors gracefully
 */
export function withSafeTheme<P extends object>(
  Component: ComponentType<P>
) {
  const WrappedComponent = (props: P) => {
    const theme = useSafeTheme()
    
    if (theme.isError) {
      return (
        <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-md">
          <div className="flex items-center gap-2 text-yellow-800">
            <AlertTriangle className="h-4 w-4" />
            <span className="text-sm font-medium">
              Theme system unavailable - using fallback styling
            </span>
          </div>
        </div>
      )
    }
    
    return <Component {...props} />
  }

  WrappedComponent.displayName = `withSafeTheme(${Component.displayName || Component.name})`
  
  return WrappedComponent
}

/**
 * Emergency theme reset utility
 */
export function resetThemeSystem() {
  try {
    // Clear all theme-related storage
    localStorage.removeItem('theme')
    localStorage.removeItem('accessibility-preferences')
    
    // Reset DOM classes
    document.documentElement.classList.remove('dark', 'light')
    document.documentElement.classList.add('light')
    document.documentElement.style.colorScheme = 'light'
    
    // Reload the page to reinitialize theme system
    window.location.reload()
  } catch (error) {
    console.error('Failed to reset theme system:', error)
    // Force page reload as last resort
    window.location.reload()
  }
}