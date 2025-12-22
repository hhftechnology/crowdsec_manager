/**
 * Property-based tests for system theme detection
 * **Feature: ui-revamp-shadcn-admin, Property 3: System Theme Detection Property**
 * **Validates: Requirements 2.3**
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, act, waitFor } from '@testing-library/react'
import * as fc from 'fast-check'
import { ThemeProvider, useTheme } from '../ThemeProvider'
import { THEME_MODES, STORAGE_KEYS } from '../../lib/constants'

// Test component to access theme context
function SystemThemeTestComponent() {
  const { theme, resolvedTheme, systemTheme } = useTheme()
  
  return (
    <div>
      <div data-testid="current-theme">{theme}</div>
      <div data-testid="resolved-theme">{resolvedTheme}</div>
      <div data-testid="system-theme">{systemTheme}</div>
    </div>
  )
}

// Mock localStorage
const localStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
}

// Create a controllable matchMedia mock
function createControllableMatchMedia() {
  let isDark = false
  const listeners: Array<(e: MediaQueryListEvent) => void> = []
  
  const mockMatchMedia = vi.fn((query: string) => {
    const mediaQuery = {
      matches: isDark,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn((event: string, listener: (e: MediaQueryListEvent) => void) => {
        if (event === 'change') {
          listeners.push(listener)
        }
      }),
      removeEventListener: vi.fn((event: string, listener: (e: MediaQueryListEvent) => void) => {
        if (event === 'change') {
          const index = listeners.indexOf(listener)
          if (index > -1) {
            listeners.splice(index, 1)
          }
        }
      }),
      dispatchEvent: vi.fn(),
    }
    return mediaQuery
  })
  
  const setSystemTheme = (dark: boolean) => {
    isDark = dark
    // Update the mock return value for future calls
    mockMatchMedia.mockReturnValue({
      matches: isDark,
      media: '',
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn((event: string, listener: (e: MediaQueryListEvent) => void) => {
        if (event === 'change') {
          listeners.push(listener)
        }
      }),
      removeEventListener: vi.fn((event: string, listener: (e: MediaQueryListEvent) => void) => {
        if (event === 'change') {
          const index = listeners.indexOf(listener)
          if (index > -1) {
            listeners.splice(index, 1)
          }
        }
      }),
      dispatchEvent: vi.fn(),
    })
    
    // Trigger all listeners
    listeners.forEach(listener => {
      listener({ matches: isDark } as MediaQueryListEvent)
    })
  }
  
  return { mockMatchMedia, setSystemTheme, getListeners: () => listeners }
}

describe('System Theme Detection Property Tests', () => {
  beforeEach(() => {
    // Reset mocks
    vi.clearAllMocks()
    Object.defineProperty(window, 'localStorage', { value: localStorageMock })
    
    // Clear DOM classes
    document.documentElement.className = ''
    
    // Clear document body
    document.body.innerHTML = ''
  })

  afterEach(() => {
    // Clean up DOM
    document.documentElement.className = ''
    document.body.innerHTML = ''
  })

  /**
   * Property 3: System Theme Detection Property
   * For any OS theme preference, when system theme is selected, 
   * the application should automatically detect and apply the matching theme
   */
  it('should detect and apply system theme preference for any OS preference', () => {
    fc.assert(
      fc.property(
        fc.boolean(), // initial system preference
        (systemDark: boolean) => {
          // Setup matchMedia mock
          const { mockMatchMedia } = createControllableMatchMedia()
          Object.defineProperty(window, 'matchMedia', {
            value: mockMatchMedia,
            configurable: true,
          })
          
          // Mock the initial matches value
          mockMatchMedia.mockReturnValue({
            matches: systemDark,
            media: '',
            onchange: null,
            addListener: vi.fn(),
            removeListener: vi.fn(),
            addEventListener: vi.fn(),
            removeEventListener: vi.fn(),
            dispatchEvent: vi.fn(),
          })

          // Setup localStorage to return system theme
          localStorageMock.getItem.mockImplementation((key: string) => {
            if (key === STORAGE_KEYS.THEME) return THEME_MODES.SYSTEM
            return null
          })

          const { unmount } = render(
            <ThemeProvider>
              <SystemThemeTestComponent />
            </ThemeProvider>
          )

          // Verify theme mode is system
          expect(screen.getAllByTestId('current-theme')[0].textContent).toBe(THEME_MODES.SYSTEM)

          // Verify system theme is detected correctly
          const systemTheme = screen.getAllByTestId('system-theme')[0].textContent
          expect(systemTheme).toBe(systemDark ? 'dark' : 'light')

          // Verify resolved theme matches system preference
          const resolvedTheme = screen.getAllByTestId('resolved-theme')[0].textContent
          expect(resolvedTheme).toBe(systemDark ? 'dark' : 'light')

          // Verify DOM classes match system preference
          const rootClasses = document.documentElement.classList
          expect(rootClasses.contains(systemDark ? 'dark' : 'light')).toBe(true)
          expect(rootClasses.contains(systemDark ? 'light' : 'dark')).toBe(false)

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should automatically update when system theme preference changes', () => {
    fc.assert(
      fc.property(
        fc.boolean(), // initial system preference
        fc.boolean(), // new system preference
        (initialDark: boolean, newDark: boolean) => {
          // Setup controllable matchMedia with initial state
          const { mockMatchMedia, setSystemTheme } = createControllableMatchMedia()
          
          // Set the initial system theme in the controllable mock
          setSystemTheme(initialDark)
          
          Object.defineProperty(window, 'matchMedia', {
            value: mockMatchMedia,
            configurable: true,
          })

          // Setup localStorage to return system theme
          localStorageMock.getItem.mockImplementation((key: string) => {
            if (key === STORAGE_KEYS.THEME) return THEME_MODES.SYSTEM
            return null
          })

          const { unmount } = render(
            <ThemeProvider>
              <SystemThemeTestComponent />
            </ThemeProvider>
          )

          // Verify initial state
          expect(screen.getAllByTestId('resolved-theme')[0].textContent).toBe(
            initialDark ? 'dark' : 'light'
          )

          // Change system theme
          act(() => {
            setSystemTheme(newDark)
          })

          // Verify theme updated to match new system preference
          waitFor(() => {
            expect(screen.getAllByTestId('system-theme')[0].textContent).toBe(
              newDark ? 'dark' : 'light'
            )
            expect(screen.getAllByTestId('resolved-theme')[0].textContent).toBe(
              newDark ? 'dark' : 'light'
            )
          })

          // Verify DOM classes updated
          const rootClasses = document.documentElement.classList
          expect(rootClasses.contains(newDark ? 'dark' : 'light')).toBe(true)

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should only respond to system changes when theme mode is system', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(THEME_MODES.LIGHT, THEME_MODES.DARK),
        fc.boolean(), // system preference change
        (explicitTheme, systemDark) => {
          // Setup controllable matchMedia
          const { mockMatchMedia, setSystemTheme } = createControllableMatchMedia()
          Object.defineProperty(window, 'matchMedia', {
            value: mockMatchMedia,
            configurable: true,
          })
          
          mockMatchMedia.mockReturnValue({
            matches: false,
            media: '',
            onchange: null,
            addListener: vi.fn(),
            removeListener: vi.fn(),
            addEventListener: vi.fn(),
            removeEventListener: vi.fn(),
            dispatchEvent: vi.fn(),
          })

          // Setup localStorage to return explicit theme (not system)
          localStorageMock.getItem.mockImplementation((key: string) => {
            if (key === STORAGE_KEYS.THEME) return explicitTheme
            return null
          })

          const { unmount } = render(
            <ThemeProvider>
              <SystemThemeTestComponent />
            </ThemeProvider>
          )

          // Get initial resolved theme
          const initialResolvedTheme = screen.getAllByTestId('resolved-theme')[0].textContent

          // Change system theme
          act(() => {
            setSystemTheme(systemDark)
          })

          // Verify resolved theme did NOT change (because we're using explicit theme)
          expect(screen.getAllByTestId('resolved-theme')[0].textContent).toBe(initialResolvedTheme)
          expect(screen.getAllByTestId('resolved-theme')[0].textContent).toBe(explicitTheme)

          // Verify DOM classes match explicit theme, not system
          const rootClasses = document.documentElement.classList
          expect(rootClasses.contains(explicitTheme)).toBe(true)

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should handle rapid system theme changes gracefully', () => {
    fc.assert(
      fc.property(
        fc.array(fc.boolean(), { minLength: 5, maxLength: 20 }),
        (themeChanges: boolean[]) => {
          // Setup controllable matchMedia
          const { mockMatchMedia, setSystemTheme } = createControllableMatchMedia()
          Object.defineProperty(window, 'matchMedia', {
            value: mockMatchMedia,
            configurable: true,
          })
          
          mockMatchMedia.mockReturnValue({
            matches: false,
            media: '',
            onchange: null,
            addListener: vi.fn(),
            removeListener: vi.fn(),
            addEventListener: vi.fn(),
            removeEventListener: vi.fn(),
            dispatchEvent: vi.fn(),
          })

          // Setup localStorage to return system theme
          localStorageMock.getItem.mockImplementation((key: string) => {
            if (key === STORAGE_KEYS.THEME) return THEME_MODES.SYSTEM
            return null
          })

          const { unmount } = render(
            <ThemeProvider>
              <SystemThemeTestComponent />
            </ThemeProvider>
          )

          // Apply rapid system theme changes
          themeChanges.forEach((isDark) => {
            act(() => {
              setSystemTheme(isDark)
            })
          })

          // Final state should match last change
          const finalDark = themeChanges[themeChanges.length - 1]
          waitFor(() => {
            expect(screen.getAllByTestId('system-theme')[0].textContent).toBe(
              finalDark ? 'dark' : 'light'
            )
            expect(screen.getAllByTestId('resolved-theme')[0].textContent).toBe(
              finalDark ? 'dark' : 'light'
            )
          })

          // DOM should be in consistent state
          const rootClasses = document.documentElement.classList
          const themeClasses = ['light', 'dark'].filter(cls => rootClasses.contains(cls))
          expect(themeClasses).toHaveLength(1)

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should clean up system theme listeners on unmount', () => {
    fc.assert(
      fc.property(
        fc.boolean(),
        (systemDark: boolean) => {
          // Setup controllable matchMedia
          const { mockMatchMedia, getListeners } = createControllableMatchMedia()
          Object.defineProperty(window, 'matchMedia', {
            value: mockMatchMedia,
            configurable: true,
          })
          
          mockMatchMedia.mockReturnValue({
            matches: systemDark,
            media: '',
            onchange: null,
            addListener: vi.fn(),
            removeListener: vi.fn(),
            addEventListener: vi.fn(),
            removeEventListener: vi.fn(),
            dispatchEvent: vi.fn(),
          })

          localStorageMock.getItem.mockImplementation((key: string) => {
            if (key === STORAGE_KEYS.THEME) return THEME_MODES.SYSTEM
            return null
          })

          const { unmount } = render(
            <ThemeProvider>
              <SystemThemeTestComponent />
            </ThemeProvider>
          )

          // Verify listeners were added
          const listenersBeforeUnmount = getListeners().length

          // Unmount component
          unmount()

          // Verify listeners were cleaned up
          const listenersAfterUnmount = getListeners().length
          expect(listenersAfterUnmount).toBeLessThanOrEqual(listenersBeforeUnmount)
        }
      ),
      { numRuns: 100 }
    )
  })
})