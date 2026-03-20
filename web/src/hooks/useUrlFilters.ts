import { useMemo, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'

/**
 * Sync filter state with URL search params so filters survive page refresh.
 * Pass the list of keys you want to track; all others are ignored.
 */
export function useUrlFilters<T extends Record<string, string | boolean | undefined>>(
  keys: string[],
  defaults: T,
): [T, (key: string, value: string | boolean) => void, () => void] {
  const [searchParams, setSearchParams] = useSearchParams()

  const filters = useMemo(() => {
    const next = { ...defaults }
    for (const key of keys) {
      const val = searchParams.get(key)
      if (val !== null) {
        if (val === 'true' || val === 'false') {
          (next as Record<string, string | boolean | undefined>)[key] = val === 'true'
        } else {
          (next as Record<string, string | boolean | undefined>)[key] = val
        }
      }
    }
    return next
  }, [defaults, keys, searchParams])

  const setFilter = useCallback((key: string, value: string | boolean) => {
    const params = new URLSearchParams(searchParams)
    if (value === undefined || value === '' || value === false) {
      params.delete(key)
    } else {
      params.set(key, String(value))
    }
    setSearchParams(params, { replace: true })
  }, [searchParams, setSearchParams])

  const resetFilters = useCallback(() => {
    const params = new URLSearchParams(searchParams)
    for (const key of keys) {
      params.delete(key)
    }
    setSearchParams(params, { replace: true })
  }, [keys, searchParams, setSearchParams])

  return [filters, setFilter, resetFilters]
}
