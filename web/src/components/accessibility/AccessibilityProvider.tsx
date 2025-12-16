import React, { createContext, useContext, useState, useEffect } from 'react'
import { useKeyboardNavigation } from '@/hooks/useKeyboardNavigation'

interface AccessibilitySettings {
  highContrast: boolean
  reducedMotion: boolean
  largeText: boolean
  keyboardNavigation: boolean
  screenReaderOptimized: boolean
}

interface AccessibilityContextType {
  settings: AccessibilitySettings
  updateSetting: (key: keyof AccessibilitySettings, value: boolean) => void
  shortcuts: any[]
  announceToScreenReader: (message: string, priority?: 'polite' | 'assertive') => void
}

const AccessibilityContext = createContext<AccessibilityContextType | undefined>(undefined)

interface AccessibilityProviderProps {
  children: React.ReactNode
}

export function AccessibilityProvider({ children }: AccessibilityProviderProps) {
  const [settings, setSettings] = useState<AccessibilitySettings>({
    highContrast: false,
    reducedMotion: false,
    largeText: false,
    keyboardNavigation: true,
    screenReaderOptimized: false
  })

  const { shortcuts } = useKeyboardNavigation({
    disabled: !settings.keyboardNavigation
  })

  // Load settings from localStorage
  useEffect(() => {
    const savedSettings = localStorage.getItem('accessibility-settings')
    if (savedSettings) {
      try {
        const parsed = JSON.parse(savedSettings)
        setSettings(prev => ({ ...prev, ...parsed }))
      } catch (error) {
        console.warn('Failed to parse accessibility settings:', error)
      }
    }

    // Detect system preferences
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const prefersHighContrast = window.matchMedia('(prefers-contrast: high)').matches
    
    setSettings(prev => ({
      ...prev,
      reducedMotion: prev.reducedMotion || prefersReducedMotion,
      highContrast: prev.highContrast || prefersHighContrast
    }))
  }, [])

  // Apply settings to document
  useEffect(() => {
    const root = document.documentElement
    
    // High contrast mode
    if (settings.highContrast) {
      root.classList.add('high-contrast')
    } else {
      root.classList.remove('high-contrast')
    }
    
    // Reduced motion
    if (settings.reducedMotion) {
      root.classList.add('reduce-motion')
    } else {
      root.classList.remove('reduce-motion')
    }
    
    // Large text
    if (settings.largeText) {
      root.classList.add('large-text')
    } else {
      root.classList.remove('large-text')
    }
    
    // Screen reader optimization
    if (settings.screenReaderOptimized) {
      root.classList.add('screen-reader-optimized')
    } else {
      root.classList.remove('screen-reader-optimized')
    }
    
    // Save to localStorage
    localStorage.setItem('accessibility-settings', JSON.stringify(settings))
  }, [settings])

  const updateSetting = (key: keyof AccessibilitySettings, value: boolean) => {
    setSettings(prev => ({ ...prev, [key]: value }))
  }

  const announceToScreenReader = (message: string, priority: 'polite' | 'assertive' = 'polite') => {
    const announcement = document.createElement('div')
    announcement.setAttribute('aria-live', priority)
    announcement.setAttribute('aria-atomic', 'true')
    announcement.className = 'sr-only'
    announcement.textContent = message
    
    document.body.appendChild(announcement)
    
    setTimeout(() => {
      if (document.body.contains(announcement)) {
        document.body.removeChild(announcement)
      }
    }, 1000)
  }

  return (
    <AccessibilityContext.Provider value={{
      settings,
      updateSetting,
      shortcuts,
      announceToScreenReader
    }}>
      {children}
    </AccessibilityContext.Provider>
  )
}

export function useAccessibility() {
  const context = useContext(AccessibilityContext)
  if (!context) {
    throw new Error('useAccessibility must be used within AccessibilityProvider')
  }
  return context
}

// Screen reader only text component
export function ScreenReaderOnly({ children }: { children: React.ReactNode }) {
  return (
    <span className="sr-only">
      {children}
    </span>
  )
}

// Skip link component for keyboard navigation
export function SkipLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-primary-foreground focus:rounded-md focus:shadow-lg"
    >
      {children}
    </a>
  )
}

// Focus indicator component
export function FocusIndicator({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-2 ${className || ''}`}>
      {children}
    </div>
  )
}