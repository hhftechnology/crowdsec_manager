import { createContext, useContext, useEffect, useState, useCallback } from "react"
import { THEME_MODES, type ThemeMode } from "../lib/constants"
import {
  type AccessibilityPreferences,
  getSystemTheme,
  getSystemAccessibilityPreferences,
  resolveTheme,
  applyTheme,
  getStoredTheme,
  storeTheme,
  getStoredAccessibilityPreferences,
  storeAccessibilityPreferences,
  createSystemThemeListener,
  createAccessibilityListeners,
} from "../lib/theme"

type ThemeProviderProps = {
  children: React.ReactNode
  defaultTheme?: ThemeMode
  enableSystemDetection?: boolean
  enableAccessibilityFeatures?: boolean
}

type ThemeProviderState = {
  theme: ThemeMode
  resolvedTheme: 'light' | 'dark'
  systemTheme: 'light' | 'dark'
  accessibility: AccessibilityPreferences
  setTheme: (theme: ThemeMode) => void
  setAccessibilityPreference: <K extends keyof AccessibilityPreferences>(
    key: K,
    value: AccessibilityPreferences[K]
  ) => void
  toggleAccessibilityPreference: (key: keyof AccessibilityPreferences) => void
}

const initialState: ThemeProviderState = {
  theme: THEME_MODES.SYSTEM,
  resolvedTheme: 'light',
  systemTheme: 'light',
  accessibility: {
    highContrast: false,
    reducedMotion: false,
    largeText: false,
    screenReaderOptimized: false,
  },
  setTheme: () => null,
  setAccessibilityPreference: () => null,
  toggleAccessibilityPreference: () => null,
}

const ThemeProviderContext = createContext<ThemeProviderState>(initialState)

export function ThemeProvider({
  children,
  defaultTheme = THEME_MODES.SYSTEM,
  enableSystemDetection = true,
  enableAccessibilityFeatures = true,
}: ThemeProviderProps) {
  const [theme, setThemeState] = useState<ThemeMode>(() => getStoredTheme() || defaultTheme)
  const [systemTheme, setSystemTheme] = useState<'light' | 'dark'>(() => getSystemTheme())
  const [accessibility, setAccessibilityState] = useState<AccessibilityPreferences>(() => ({
    ...getStoredAccessibilityPreferences(),
    ...getSystemAccessibilityPreferences(),
  }))

  const resolvedTheme = resolveTheme(theme, systemTheme)

  // Apply theme and accessibility preferences to DOM
  useEffect(() => {
    applyTheme(resolvedTheme, accessibility)
  }, [resolvedTheme, accessibility])

  // Set up system theme detection
  useEffect(() => {
    if (!enableSystemDetection) return

    const cleanup = createSystemThemeListener((newSystemTheme) => {
      setSystemTheme(newSystemTheme)
    })

    return cleanup
  }, [enableSystemDetection])

  // Set up accessibility preferences detection
  useEffect(() => {
    if (!enableAccessibilityFeatures) return

    const cleanup = createAccessibilityListeners((newPreferences) => {
      setAccessibilityState(prev => ({
        ...prev,
        ...newPreferences,
      }))
    })

    return cleanup
  }, [enableAccessibilityFeatures])

  // Theme setter with persistence
  const setTheme = useCallback((newTheme: ThemeMode) => {
    setThemeState(newTheme)
    storeTheme(newTheme)
  }, [])

  // Accessibility preference setter
  const setAccessibilityPreference = useCallback(<K extends keyof AccessibilityPreferences>(
    key: K,
    value: AccessibilityPreferences[K]
  ) => {
    setAccessibilityState(prev => {
      const newPreferences = { ...prev, [key]: value }
      storeAccessibilityPreferences(newPreferences)
      return newPreferences
    })
  }, [])

  // Accessibility preference toggler
  const toggleAccessibilityPreference = useCallback((key: keyof AccessibilityPreferences) => {
    setAccessibilityState(prev => {
      const newPreferences = { ...prev, [key]: !prev[key] }
      storeAccessibilityPreferences(newPreferences)
      return newPreferences
    })
  }, [])

  const value: ThemeProviderState = {
    theme,
    resolvedTheme,
    systemTheme,
    accessibility,
    setTheme,
    setAccessibilityPreference,
    toggleAccessibilityPreference,
  }

  return (
    <ThemeProviderContext.Provider value={value}>
      {children}
    </ThemeProviderContext.Provider>
  )
}

export const useTheme = () => {
  const context = useContext(ThemeProviderContext)

  if (context === undefined)
    throw new Error("useTheme must be used within a ThemeProvider")

  return context
}

// Convenience hook for accessibility preferences
export const useAccessibility = () => {
  const { accessibility, setAccessibilityPreference, toggleAccessibilityPreference } = useTheme()
  
  return {
    accessibility,
    setAccessibilityPreference,
    toggleAccessibilityPreference,
  }
}
