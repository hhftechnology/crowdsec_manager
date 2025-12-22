import * as React from "react"

export interface AsyncOperationState<T> {
  data: T | null
  loading: boolean
  error: Error | null
  isSuccess: boolean
  isError: boolean
}

export interface AsyncOperationOptions {
  onSuccess?: (data: any) => void
  onError?: (error: Error) => void
  retryCount?: number
  retryDelay?: number
}

/**
 * Hook for managing async operations with loading, error, and retry logic
 */
export function useAsyncOperation<T = any>(
  operation: () => Promise<T>,
  options: AsyncOperationOptions = {}
) {
  const {
    onSuccess,
    onError,
    retryCount = 3,
    retryDelay = 1000
  } = options

  const [state, setState] = React.useState<AsyncOperationState<T>>({
    data: null,
    loading: false,
    error: null,
    isSuccess: false,
    isError: false
  })

  const [currentRetry, setCurrentRetry] = React.useState(0)
  const retryTimeoutRef = React.useRef<NodeJS.Timeout>()

  const execute = React.useCallback(async (resetRetry = true) => {
    if (resetRetry) {
      setCurrentRetry(0)
    }

    setState(prev => ({
      ...prev,
      loading: true,
      error: null,
      isError: false,
      isSuccess: false
    }))

    try {
      const result = await operation()
      
      setState({
        data: result,
        loading: false,
        error: null,
        isSuccess: true,
        isError: false
      })

      onSuccess?.(result)
      return result
    } catch (error) {
      const errorObj = error instanceof Error ? error : new Error(String(error))
      
      setState({
        data: null,
        loading: false,
        error: errorObj,
        isSuccess: false,
        isError: true
      })

      onError?.(errorObj)
      throw errorObj
    }
  }, [operation, onSuccess, onError])

  const retry = React.useCallback(async () => {
    if (currentRetry < retryCount) {
      setCurrentRetry(prev => prev + 1)
      
      // Clear any existing timeout
      if (retryTimeoutRef.current) {
        clearTimeout(retryTimeoutRef.current)
      }

      // Delay before retry
      return new Promise<T>((resolve, reject) => {
        retryTimeoutRef.current = setTimeout(async () => {
          try {
            const result = await execute(false)
            resolve(result)
          } catch (error) {
            reject(error)
          }
        }, retryDelay * (currentRetry + 1)) // Exponential backoff
      })
    } else {
      throw new Error(`Operation failed after ${retryCount} retries`)
    }
  }, [currentRetry, retryCount, retryDelay, execute])

  const reset = React.useCallback(() => {
    setState({
      data: null,
      loading: false,
      error: null,
      isSuccess: false,
      isError: false
    })
    setCurrentRetry(0)
    
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current)
    }
  }, [])

  // Cleanup timeout on unmount
  React.useEffect(() => {
    return () => {
      if (retryTimeoutRef.current) {
        clearTimeout(retryTimeoutRef.current)
      }
    }
  }, [])

  return {
    ...state,
    execute,
    retry,
    reset,
    canRetry: currentRetry < retryCount,
    retryCount: currentRetry
  }
}

/**
 * Hook for managing multiple async operations
 */
export function useAsyncOperations<T extends Record<string, () => Promise<any>>>(
  operations: T,
  options: AsyncOperationOptions = {}
) {
  type OperationKeys = keyof T
  type OperationResults = {
    [K in OperationKeys]: AsyncOperationState<Awaited<ReturnType<T[K]>>>
  }

  const [states, setStates] = React.useState<OperationResults>(() => {
    const initialStates = {} as OperationResults
    Object.keys(operations).forEach(key => {
      initialStates[key as OperationKeys] = {
        data: null,
        loading: false,
        error: null,
        isSuccess: false,
        isError: false
      }
    })
    return initialStates
  })

  const execute = React.useCallback(async (operationKey: OperationKeys) => {
    const operation = operations[operationKey]
    if (!operation) {
      throw new Error(`Operation ${String(operationKey)} not found`)
    }

    setStates(prev => ({
      ...prev,
      [operationKey]: {
        ...prev[operationKey],
        loading: true,
        error: null,
        isError: false,
        isSuccess: false
      }
    }))

    try {
      const result = await operation()
      
      setStates(prev => ({
        ...prev,
        [operationKey]: {
          data: result,
          loading: false,
          error: null,
          isSuccess: true,
          isError: false
        }
      }))

      options.onSuccess?.(result)
      return result
    } catch (error) {
      const errorObj = error instanceof Error ? error : new Error(String(error))
      
      setStates(prev => ({
        ...prev,
        [operationKey]: {
          data: null,
          loading: false,
          error: errorObj,
          isSuccess: false,
          isError: true
        }
      }))

      options.onError?.(errorObj)
      throw errorObj
    }
  }, [operations, options])

  const executeAll = React.useCallback(async () => {
    const results = await Promise.allSettled(
      Object.keys(operations).map(key => execute(key as OperationKeys))
    )
    
    return results
  }, [operations, execute])

  const reset = React.useCallback((operationKey?: OperationKeys) => {
    if (operationKey) {
      setStates(prev => ({
        ...prev,
        [operationKey]: {
          data: null,
          loading: false,
          error: null,
          isSuccess: false,
          isError: false
        }
      }))
    } else {
      setStates(prev => {
        const resetStates = {} as OperationResults
        Object.keys(prev).forEach(key => {
          resetStates[key as OperationKeys] = {
            data: null,
            loading: false,
            error: null,
            isSuccess: false,
            isError: false
          }
        })
        return resetStates
      })
    }
  }, [])

  const isAnyLoading = React.useMemo(() => {
    return Object.values(states).some(state => state.loading)
  }, [states])

  const hasAnyError = React.useMemo(() => {
    return Object.values(states).some(state => state.isError)
  }, [states])

  const allSuccessful = React.useMemo(() => {
    return Object.values(states).every(state => state.isSuccess)
  }, [states])

  return {
    states,
    execute,
    executeAll,
    reset,
    isAnyLoading,
    hasAnyError,
    allSuccessful
  }
}

/**
 * Hook for debounced async operations
 */
export function useDebouncedAsyncOperation<T = any>(
  operation: () => Promise<T>,
  delay: number = 300,
  options: AsyncOperationOptions = {}
) {
  const asyncOp = useAsyncOperation(operation, options)
  const timeoutRef = React.useRef<NodeJS.Timeout>()

  const debouncedExecute = React.useCallback(() => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
    }

    timeoutRef.current = setTimeout(() => {
      asyncOp.execute()
    }, delay)
  }, [asyncOp.execute, delay])

  React.useEffect(() => {
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current)
      }
    }
  }, [])

  return {
    ...asyncOp,
    execute: debouncedExecute,
    executeImmediate: asyncOp.execute
  }
}