/**
 * Theme utilities and configuration
 * Netflix-inspired theme system with enhanced functionality
 */

import { THEME_MODES, STORAGE_KEYS, type ThemeMode } from './constants'

/**
 * Theme configuration interface
 */
export interface ThemeConfig {
  mode: ThemeMode
  systemPreference: 'light' | 'dark'
  resolvedTheme: 'light' | 'dark'
  highContrast: boolean
  reducedMotion: boolean
  largeText: boolean
}

/**
 * Accessibility preferences interface
 */
export interface AccessibilityPreferences {
  highContrast: boolean
  reducedMotion: boolean
  largeText: boolean
  screenReaderOptimized: boolean
}

/**
 * Get system theme preference
 */
export function getSystemTheme(): 'light' | 'dark' {
  if (typeof window === 'undefined') return 'light'
  
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

/**
 * Get system accessibility preferences
 */
export function getSystemAccessibilityPreferences(): Partial<AccessibilityPreferences> {
  if (typeof window === 'undefined') return {}
  
  return {
    reducedMotion: window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    highContrast: window.matchMedia('(prefers-contrast: high)').matches,
  }
}

/**
 * Resolve theme mode to actual theme
 */
export function resolveTheme(mode: ThemeMode, systemPreference?: 'light' | 'dark'): 'light' | 'dark' {
  if (mode === THEME_MODES.SYSTEM) {
    return systemPreference || getSystemTheme()
  }
  return mode as 'light' | 'dark'
}

/**
 * Apply theme to document with smooth transitions
 */
export function applyTheme(theme: 'light' | 'dark', accessibility?: AccessibilityPreferences) {
  if (typeof document === 'undefined') return
  
  const root = document.documentElement
  
  // Temporarily disable transitions to prevent white flashes
  root.classList.add('no-transition')
  
  // Remove existing theme classes
  root.classList.remove('light', 'dark')
  
  // Apply theme
  root.classList.add(theme)
  
  // Apply accessibility preferences
  if (accessibility) {
    root.classList.toggle('high-contrast', accessibility.highContrast)
    root.classList.toggle('reduce-motion', accessibility.reducedMotion)
    root.classList.toggle('large-text', accessibility.largeText)
    root.classList.toggle('screen-reader-optimized', accessibility.screenReaderOptimized)
  }
  
  // Re-enable transitions after a brief delay
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      root.classList.remove('no-transition')
    })
  })
}

/**
 * Get stored theme preference
 */
export function getStoredTheme(): ThemeMode {
  if (typeof localStorage === 'undefined') return THEME_MODES.SYSTEM
  
  const stored = localStorage.getItem(STORAGE_KEYS.THEME)
  if (stored && Object.values(THEME_MODES).includes(stored as ThemeMode)) {
    return stored as ThemeMode
  }
  
  return THEME_MODES.SYSTEM
}

/**
 * Store theme preference
 */
export function storeTheme(theme: ThemeMode) {
  if (typeof localStorage === 'undefined') return
  
  localStorage.setItem(STORAGE_KEYS.THEME, theme)
}

/**
 * Get stored accessibility preferences
 */
export function getStoredAccessibilityPreferences(): AccessibilityPreferences {
  if (typeof localStorage === 'undefined') {
    return {
      highContrast: false,
      reducedMotion: false,
      largeText: false,
      screenReaderOptimized: false,
    }
  }
  
  const stored = localStorage.getItem(STORAGE_KEYS.ACCESSIBILITY_PREFERENCES)
  if (stored) {
    try {
      const parsed = JSON.parse(stored)
      return {
        highContrast: Boolean(parsed.highContrast),
        reducedMotion: Boolean(parsed.reducedMotion),
        largeText: Boolean(parsed.largeText),
        screenReaderOptimized: Boolean(parsed.screenReaderOptimized),
      }
    } catch {
      // Fall through to defaults
    }
  }
  
  return {
    highContrast: false,
    reducedMotion: false,
    largeText: false,
    screenReaderOptimized: false,
  }
}

/**
 * Store accessibility preferences
 */
export function storeAccessibilityPreferences(preferences: AccessibilityPreferences) {
  if (typeof localStorage === 'undefined') return
  
  localStorage.setItem(STORAGE_KEYS.ACCESSIBILITY_PREFERENCES, JSON.stringify(preferences))
}

/**
 * Create media query listener for system theme changes
 */
export function createSystemThemeListener(callback: (theme: 'light' | 'dark') => void) {
  if (typeof window === 'undefined') return () => {}
  
  const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
  
  const listener = (e: MediaQueryListEvent) => {
    callback(e.matches ? 'dark' : 'light')
  }
  
  mediaQuery.addEventListener('change', listener)
  
  return () => {
    mediaQuery.removeEventListener('change', listener)
  }
}

/**
 * Create media query listeners for accessibility preferences
 */
export function createAccessibilityListeners(
  callback: (preferences: Partial<AccessibilityPreferences>) => void
) {
  if (typeof window === 'undefined') return () => {}
  
  const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
  const highContrastQuery = window.matchMedia('(prefers-contrast: high)')
  
  const reducedMotionListener = (e: MediaQueryListEvent) => {
    callback({ reducedMotion: e.matches })
  }
  
  const highContrastListener = (e: MediaQueryListEvent) => {
    callback({ highContrast: e.matches })
  }
  
  reducedMotionQuery.addEventListener('change', reducedMotionListener)
  highContrastQuery.addEventListener('change', highContrastListener)
  
  return () => {
    reducedMotionQuery.removeEventListener('change', reducedMotionListener)
    highContrastQuery.removeEventListener('change', highContrastListener)
  }
}

/**
 * Validate theme mode
 */
export function isValidThemeMode(value: string): value is ThemeMode {
  return Object.values(THEME_MODES).includes(value as ThemeMode)
}

/**
 * Get CSS custom property value
 */
export function getCSSCustomProperty(property: string): string {
  if (typeof document === 'undefined') return ''
  
  return getComputedStyle(document.documentElement)
    .getPropertyValue(property)
    .trim()
}

/**
 * Set CSS custom property value
 */
export function setCSSCustomProperty(property: string, value: string) {
  if (typeof document === 'undefined') return
  
  document.documentElement.style.setProperty(property, value)
}