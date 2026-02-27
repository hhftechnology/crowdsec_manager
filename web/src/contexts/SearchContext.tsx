import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'

type SearchScope = 'global' | 'hub' | 'logs' | 'scenarios' | 'bouncers' | 'alerts' | 'decisions'

interface SearchState {
  query: string
  scope: SearchScope
}

interface SearchContextValue extends SearchState {
  setQuery: (query: string) => void
  setScope: (scope: SearchScope) => void
  clear: () => void
}

const SearchContext = createContext<SearchContextValue | undefined>(undefined)

interface SearchProviderProps {
  children: ReactNode
}

export function SearchProvider({ children }: SearchProviderProps) {
  const [state, setState] = useState<SearchState>({
    query: '',
    scope: 'global',
  })

  const setQuery = useCallback((query: string) => {
    setState((prev) => ({ ...prev, query }))
  }, [])

  const setScope = useCallback((scope: SearchScope) => {
    setState((prev) => ({ ...prev, scope }))
  }, [])

  const clear = useCallback(() => {
    setState((prev) => ({ ...prev, query: '' }))
  }, [])

  const value = useMemo<SearchContextValue>(() => ({
    ...state,
    setQuery,
    setScope,
    clear,
  }), [state, setQuery, setScope, clear])

  return (
    <SearchContext.Provider value={value}>
      {children}
    </SearchContext.Provider>
  )
}

export function useSearch() {
  const context = useContext(SearchContext)
  if (!context) {
    throw new Error('useSearch must be used within a SearchProvider')
  }
  return context
}

export type { SearchScope }
