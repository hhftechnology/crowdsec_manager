import { useEffect, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'

interface KeyboardShortcut {
  key: string
  ctrlKey?: boolean
  altKey?: boolean
  shiftKey?: boolean
  metaKey?: boolean
  action: () => void
  description: string
  category?: string
}

interface UseKeyboardNavigationOptions {
  shortcuts?: KeyboardShortcut[]
  disabled?: boolean
  preventDefault?: boolean
}

/**
 * Hook for managing keyboard navigation and shortcuts
 * Provides comprehensive keyboard accessibility for the application
 */
export function useKeyboardNavigation(options: UseKeyboardNavigationOptions = {}) {
  const { shortcuts = [], disabled = false, preventDefault = true } = options
  const navigate = useNavigate()
  const shortcutsRef = useRef<KeyboardShortcut[]>([])
  
  // Default application shortcuts
  const defaultShortcuts: KeyboardShortcut[] = [
    {
      key: 'h',
      altKey: true,
      action: () => navigate('/'),
      description: 'Go to Dashboard',
      category: 'Navigation'
    },
    {
      key: 'd',
      altKey: true,
      action: () => navigate('/decisions'),
      description: 'Go to Decisions',
      category: 'Navigation'
    },
    {
      key: 'a',
      altKey: true,
      action: () => navigate('/alerts'),
      description: 'Go to Alerts',
      category: 'Navigation'
    },
    {
      key: 'b',
      altKey: true,
      action: () => navigate('/bouncers'),
      description: 'Go to Bouncers',
      category: 'Navigation'
    },
    {
      key: 'w',
      altKey: true,
      action: () => navigate('/whitelist'),
      description: 'Go to Whitelist',
      category: 'Navigation'
    },
    {
      key: 'l',
      altKey: true,
      action: () => navigate('/logs'),
      description: 'Go to Logs',
      category: 'Navigation'
    },
    {
      key: 's',
      altKey: true,
      action: () => navigate('/configuration'),
      description: 'Go to Settings',
      category: 'Navigation'
    },
    {
      key: '/',
      ctrlKey: true,
      action: () => {
        // Focus search input if available
        const searchInput = document.querySelector('[data-search-input]') as HTMLInputElement
        if (searchInput) {
          searchInput.focus()
        }
      },
      description: 'Focus Search',
      category: 'Interface'
    },
    {
      key: 'k',
      ctrlKey: true,
      action: () => {
        // Open command palette
        const commandTrigger = document.querySelector('[data-command-trigger]') as HTMLButtonElement
        if (commandTrigger) {
          commandTrigger.click()
        }
      },
      description: 'Open Command Palette',
      category: 'Interface'
    },
    {
      key: 'Escape',
      action: () => {
        // Close any open modals or dropdowns
        const activeElement = document.activeElement as HTMLElement
        if (activeElement && activeElement.blur) {
          activeElement.blur()
        }
        
        // Close modals
        const closeButtons = document.querySelectorAll('[data-close-modal]')
        closeButtons.forEach(button => {
          if (button instanceof HTMLElement) {
            button.click()
          }
        })
      },
      description: 'Close Modal/Dropdown',
      category: 'Interface'
    },
    {
      key: '?',
      shiftKey: true,
      action: () => {
        // Show keyboard shortcuts help
        const helpTrigger = document.querySelector('[data-help-trigger]') as HTMLButtonElement
        if (helpTrigger) {
          helpTrigger.click()
        }
      },
      description: 'Show Keyboard Shortcuts',
      category: 'Help'
    }
  ]
  
  // Combine default and custom shortcuts
  shortcutsRef.current = [...defaultShortcuts, ...shortcuts]
  
  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    if (disabled) return
    
    // Don't trigger shortcuts when typing in inputs
    const target = event.target as HTMLElement
    if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.contentEditable === 'true') {
      // Allow Escape to blur inputs
      if (event.key === 'Escape') {
        target.blur()
        return
      }
      return
    }
    
    // Find matching shortcut
    const matchingShortcut = shortcutsRef.current.find(shortcut => {
      return (
        shortcut.key.toLowerCase() === event.key.toLowerCase() &&
        !!shortcut.ctrlKey === event.ctrlKey &&
        !!shortcut.altKey === event.altKey &&
        !!shortcut.shiftKey === event.shiftKey &&
        !!shortcut.metaKey === event.metaKey
      )
    })
    
    if (matchingShortcut) {
      if (preventDefault) {
        event.preventDefault()
      }
      matchingShortcut.action()
    }
  }, [disabled, preventDefault])
  
  useEffect(() => {
    if (disabled) return
    
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [handleKeyDown, disabled])
  
  // Return shortcuts for help display
  return {
    shortcuts: shortcutsRef.current,
    addShortcut: (shortcut: KeyboardShortcut) => {
      shortcutsRef.current.push(shortcut)
    },
    removeShortcut: (key: string) => {
      shortcutsRef.current = shortcutsRef.current.filter(s => s.key !== key)
    }
  }
}

/**
 * Hook for managing focus within a container (focus trap)
 * Useful for modals and dropdowns
 */
export function useFocusTrap(containerRef: React.RefObject<HTMLElement>, active: boolean = true) {
  useEffect(() => {
    if (!active || !containerRef.current) return
    
    const container = containerRef.current
    const focusableElements = container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    )
    
    const firstElement = focusableElements[0] as HTMLElement
    const lastElement = focusableElements[focusableElements.length - 1] as HTMLElement
    
    const handleTabKey = (event: KeyboardEvent) => {
      if (event.key !== 'Tab') return
      
      if (event.shiftKey) {
        if (document.activeElement === firstElement) {
          event.preventDefault()
          lastElement?.focus()
        }
      } else {
        if (document.activeElement === lastElement) {
          event.preventDefault()
          firstElement?.focus()
        }
      }
    }
    
    // Focus first element when trap activates
    firstElement?.focus()
    
    container.addEventListener('keydown', handleTabKey)
    return () => container.removeEventListener('keydown', handleTabKey)
  }, [containerRef, active])
}

/**
 * Hook for managing roving tabindex (arrow key navigation)
 * Useful for lists, menus, and toolbars
 */
export function useRovingTabIndex(
  containerRef: React.RefObject<HTMLElement>,
  options: {
    direction?: 'horizontal' | 'vertical' | 'both'
    loop?: boolean
    disabled?: boolean
  } = {}
) {
  const { direction = 'vertical', loop = true, disabled = false } = options
  
  useEffect(() => {
    if (disabled || !containerRef.current) return
    
    const container = containerRef.current
    const items = Array.from(
      container.querySelectorAll('[role="menuitem"], [role="option"], [data-roving-item]')
    ) as HTMLElement[]
    
    if (items.length === 0) return
    
    // Set initial tabindex
    items.forEach((item, index) => {
      item.tabIndex = index === 0 ? 0 : -1
    })
    
    const handleKeyDown = (event: KeyboardEvent) => {
      const currentIndex = items.findIndex(item => item === document.activeElement)
      if (currentIndex === -1) return
      
      let nextIndex = currentIndex
      
      switch (event.key) {
        case 'ArrowDown':
          if (direction === 'vertical' || direction === 'both') {
            event.preventDefault()
            nextIndex = currentIndex + 1
            if (nextIndex >= items.length) {
              nextIndex = loop ? 0 : items.length - 1
            }
          }
          break
        case 'ArrowUp':
          if (direction === 'vertical' || direction === 'both') {
            event.preventDefault()
            nextIndex = currentIndex - 1
            if (nextIndex < 0) {
              nextIndex = loop ? items.length - 1 : 0
            }
          }
          break
        case 'ArrowRight':
          if (direction === 'horizontal' || direction === 'both') {
            event.preventDefault()
            nextIndex = currentIndex + 1
            if (nextIndex >= items.length) {
              nextIndex = loop ? 0 : items.length - 1
            }
          }
          break
        case 'ArrowLeft':
          if (direction === 'horizontal' || direction === 'both') {
            event.preventDefault()
            nextIndex = currentIndex - 1
            if (nextIndex < 0) {
              nextIndex = loop ? items.length - 1 : 0
            }
          }
          break
        case 'Home':
          event.preventDefault()
          nextIndex = 0
          break
        case 'End':
          event.preventDefault()
          nextIndex = items.length - 1
          break
      }
      
      if (nextIndex !== currentIndex) {
        items[currentIndex].tabIndex = -1
        items[nextIndex].tabIndex = 0
        items[nextIndex].focus()
      }
    }
    
    container.addEventListener('keydown', handleKeyDown)
    return () => container.removeEventListener('keydown', handleKeyDown)
  }, [containerRef, direction, loop, disabled])
}

/**
 * Hook for announcing screen reader messages
 */
export function useScreenReader() {
  const announce = useCallback((message: string, priority: 'polite' | 'assertive' = 'polite') => {
    const announcement = document.createElement('div')
    announcement.setAttribute('aria-live', priority)
    announcement.setAttribute('aria-atomic', 'true')
    announcement.className = 'sr-only'
    announcement.textContent = message
    
    document.body.appendChild(announcement)
    
    // Remove after announcement
    setTimeout(() => {
      document.body.removeChild(announcement)
    }, 1000)
  }, [])
  
  return { announce }
}