import { ComponentType, ReactNode, createContext, useCallback, useContext, useState } from "react"

export interface LoadingState {
  id: string
  label: string
  context?: string
  startTime: Date
  progress?: number
  metadata?: Record<string, any>
}

export interface LoadingContextType {
  loadingStates: LoadingState[]
  startLoading: (label: string, context?: string, metadata?: Record<string, any>) => string
  updateLoading: (id: string, updates: Partial<Pick<LoadingState, 'label' | 'progress' | 'metadata'>>) => void
  stopLoading: (id: string) => void
  stopAllLoading: (context?: string) => void
  isLoading: (context?: string) => boolean
  getLoadingByContext: (context: string) => LoadingState[]
  globalLoading: boolean
}

const LoadingContext = createContext<LoadingContextType | undefined>(undefined)

export interface LoadingProviderProps {
  children: ReactNode
  maxStates?: number
}

export function LoadingProvider({ children, maxStates = 100 }: LoadingProviderProps) {
  const [loadingStates, setLoadingStates] = useState<LoadingState[]>([])

  const startLoading = useCallback((
    label: string, 
    context?: string, 
    metadata?: Record<string, any>
  ): string => {
    const loadingState: LoadingState = {
      id: `loading-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`, 
      label, 
      context, 
      startTime: new Date(), 
      progress: undefined, 
      metadata
    }

    setLoadingStates(prev => {
      const newStates = [loadingState, ...prev]
      // Keep only the most recent loading states
      return newStates.slice(0, maxStates)
    })

    return loadingState.id
  }, [maxStates])

  const updateLoading = useCallback((
    id: string, 
    updates: Partial<Pick<LoadingState, 'label' | 'progress' | 'metadata'>>
  ) => {
    setLoadingStates(prev => prev.map(state => 
      state.id === id ? { ...state, ...updates } : state
    ))
  }, [])

  const stopLoading = useCallback((id: string) => {
    setLoadingStates(prev => prev.filter(state => state.id !== id))
  }, [])

  const stopAllLoading = useCallback((context?: string) => {
    if (context) {
      setLoadingStates(prev => prev.filter(state => state.context !== context))
    } else {
      setLoadingStates([])
    }
  }, [])

  const isLoading = useCallback((context?: string) => {
    if (context) {
      return loadingStates.some(state => state.context === context)
    }
    return loadingStates.length > 0
  }, [loadingStates])

  const getLoadingByContext = useCallback((context: string) => {
    return loadingStates.filter(state => state.context === context)
  }, [loadingStates])

  const globalLoading = loadingStates.length > 0

  const contextValue: LoadingContextType = {
    loadingStates, 
    startLoading, 
    updateLoading, 
    stopLoading, 
    stopAllLoading, 
    isLoading, 
    getLoadingByContext, 
    globalLoading
  }

  return (
    <LoadingContext.Provider value={contextValue}>
      {children}
    </LoadingContext.Provider>
  )
}

export function useLoading() {
  const context = useContext(LoadingContext)
  if (context === undefined) {
    throw new Error('useLoading must be used within a LoadingProvider')
  }
  return context
}

/**
 * Hook to manage loading state for a specific context
 */
export function useContextualLoading(context: string) {
  const { 
    startLoading, 
    updateLoading, 
    stopLoading, 
    stopAllLoading, 
    isLoading, 
    getLoadingByContext 
  } = useLoading()

  const startContextLoading = useCallback((
    label: string, 
    metadata?: Record<string, any>
  ) => {
    return startLoading(label, context, metadata)
  }, [startLoading, context])

  const stopContextLoading = useCallback(() => {
    stopAllLoading(context)
  }, [stopAllLoading, context])

  const contextLoading = isLoading(context)
  const contextLoadingStates = getLoadingByContext(context)

  return {
    startLoading: startContextLoading, 
    updateLoading, 
    stopLoading, 
    stopAllLoading: stopContextLoading, 
    isLoading: contextLoading, 
    loadingStates: contextLoadingStates
  }
}

/**
 * Hook to wrap async operations with loading state management
 */
export function useAsyncWithLoading<T extends (...args: any[]) => Promise<any>>(
  asyncFn: T, 
  loadingLabel: string, 
  context?: string
): [T, boolean] {
  const { startLoading, stopLoading, isLoading } = useLoading()
  const [operationId, setOperationId] = useState<string | null>(null)

  const wrappedFn = useCallback(async (...args: Parameters<T>) => {
    const id = startLoading(loadingLabel, context)
    setOperationId(id)

    try {
      const result = await asyncFn(...args)
      return result
    } finally {
      stopLoading(id)
      setOperationId(null)
    }
  }, [asyncFn, startLoading, stopLoading, loadingLabel, context]) as T

  const isCurrentlyLoading = operationId ? true : isLoading(context)

  return [wrappedFn, isCurrentlyLoading]
}

/**
 * Hook for managing progressive loading operations
 */
export function useProgressiveLoading(context: string) {
  const { startLoading, updateLoading, stopLoading } = useLoading()
  const [currentId, setCurrentId] = useState<string | null>(null)

  const startProgress = useCallback((label: string) => {
    const id = startLoading(label, context, { progress: 0 })
    setCurrentId(id)
    return id
  }, [startLoading, context])

  const updateProgress = useCallback((progress: number, label?: string) => {
    if (currentId) {
      const updates: any = { progress: Math.max(0, Math.min(100, progress)) }
      if (label) updates.label = label
      updateLoading(currentId, updates)
    }
  }, [currentId, updateLoading])

  const completeProgress = useCallback(() => {
    if (currentId) {
      stopLoading(currentId)
      setCurrentId(null)
    }
  }, [currentId, stopLoading])

  return {
    startProgress, 
    updateProgress, 
    completeProgress, 
    isActive: currentId !== null
  }
}

/**
 * Higher-order component to wrap components with loading state management
 */
export function withLoadingState<P extends object>(
  Component: ComponentType<P>, 
  context?: string
) {
  const WrappedComponent = (props: P) => {
    const contextualLoading = useContextualLoading(
      context || Component.displayName || Component.name || 'component'
    )

    return <Component {...props} loading={contextualLoading} />
  }

  WrappedComponent.displayName = `withLoadingState(${Component.displayName || Component.name})`

  return WrappedComponent
}