import { useState, useCallback, useEffect } from 'react'
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

  // Initialize from URL or defaults
  const [filters, setFilters] = useState<T>(() => {
    const init = { ...defaults }
    for (const key of keys) {
      const val = searchParams.get(key)
      if (val !== null) {
        if (val === 'true' || val === 'false') {
          (init as Record<string, string | boolean | undefined>)[key] = val === 'true'
        } else {
          (init as Record<string, string | boolean | undefined>)[key] = val
        }
      }
    }
    return init
  })

  // Sync filters → URL
  useEffect(() => {
    const params = new URLSearchParams()
    for (const key of keys) {
      const val = filters[key]
      if (val !== undefined && val !== '' && val !== false) {
        params.set(key, String(val))
      }
    }
    setSearchParams(params, { replace: true })
  }, [filters, keys, setSearchParams])

  const setFilter = useCallback((key: string, value: string | boolean) => {
    setFilters(prev => ({ ...prev, [key]: value }))
  }, [])

  const resetFilters = useCallback(() => {
    setFilters({ ...defaults })
  }, [defaults])

  return [filters, setFilter, resetFilters]
}
