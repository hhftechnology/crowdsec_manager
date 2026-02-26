import { useState, useCallback } from 'react'

interface AsyncState<T> {
  data: T | null
  error: string | null
  loading: boolean
}

interface UseAsyncOperationReturn<T, Args extends unknown[]> {
  data: T | null
  error: string | null
  loading: boolean
  execute: (...args: Args) => Promise<T | null>
  reset: () => void
}

/**
 * Generic hook for managing async operation state (loading, error, data).
 * Useful for form submissions, one-off API calls, etc.
 *
 * @param asyncFn - The async function to wrap
 * @returns State object with execute/reset controls
 */
export function useAsyncOperation<T, Args extends unknown[] = []>(
  asyncFn: (...args: Args) => Promise<T>
): UseAsyncOperationReturn<T, Args> {
  const [state, setState] = useState<AsyncState<T>>({
    data: null,
    error: null,
    loading: false,
  })

  const execute = useCallback(
    async (...args: Args): Promise<T | null> => {
      setState({ data: null, error: null, loading: true })
      try {
        const result = await asyncFn(...args)
        setState({ data: result, error: null, loading: false })
        return result
      } catch (err) {
        const message = err instanceof Error ? err.message : 'An error occurred'
        setState({ data: null, error: message, loading: false })
        return null
      }
    },
    [asyncFn]
  )

  const reset = useCallback(() => {
    setState({ data: null, error: null, loading: false })
  }, [])

  return {
    ...state,
    execute,
    reset,
  }
}
