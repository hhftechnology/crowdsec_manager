/**
 * Accessibility utilities and helpers
 * Comprehensive accessibility support for the CrowdSec Manager UI
 */

/**
 * Skip link component data
 */
export interface SkipLink {
  href: string
  label: string
}

/**
 * Default skip links for the application
 */
export const DEFAULT_SKIP_LINKS: SkipLink[] = [
  { href: '#main-content', label: 'Skip to main content' },
  { href: '#navigation', label: 'Skip to navigation' },
  { href: '#search', label: 'Skip to search' },
]

/**
 * Keyboard navigation keys
 */
export const KEYBOARD_KEYS = {
  TAB: 'Tab',
  ENTER: 'Enter',
  SPACE: ' ',
  ESCAPE: 'Escape',
  ARROW_UP: 'ArrowUp',
  ARROW_DOWN: 'ArrowDown',
  ARROW_LEFT: 'ArrowLeft',
  ARROW_RIGHT: 'ArrowRight',
  HOME: 'Home',
  END: 'End',
} as const

/**
 * ARIA live region priorities
 */
export const ARIA_LIVE_PRIORITIES = {
  POLITE: 'polite',
  ASSERTIVE: 'assertive',
  OFF: 'off',
} as const

/**
 * Focus management utilities
 */
export class FocusManager {
  private static focusableSelectors = [
    'button:not([disabled])',
    '[href]',
    'input:not([disabled])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
    '[role="button"]:not([disabled])',
    '[role="menuitem"]:not([disabled])',
    '[role="option"]:not([disabled])',
  ].join(', ')

  /**
   * Get all focusable elements within a container
   */
  static getFocusableElements(container: HTMLElement): HTMLElement[] {
    return Array.from(container.querySelectorAll(this.focusableSelectors))
  }

  /**
   * Get the first focusable element in a container
   */
  static getFirstFocusableElement(container: HTMLElement): HTMLElement | null {
    const elements = this.getFocusableElements(container)
    return elements[0] || null
  }

  /**
   * Get the last focusable element in a container
   */
  static getLastFocusableElement(container: HTMLElement): HTMLElement | null {
    const elements = this.getFocusableElements(container)
    return elements[elements.length - 1] || null
  }

  /**
   * Trap focus within a container (for modals, dropdowns)
   */
  static trapFocus(container: HTMLElement, event: KeyboardEvent): void {
    if (event.key !== KEYBOARD_KEYS.TAB) return

    const focusableElements = this.getFocusableElements(container)
    if (focusableElements.length === 0) return

    const firstElement = focusableElements[0]
    const lastElement = focusableElements[focusableElements.length - 1]

    if (event.shiftKey) {
      // Shift + Tab
      if (document.activeElement === firstElement) {
        event.preventDefault()
        lastElement.focus()
      }
    } else {
      // Tab
      if (document.activeElement === lastElement) {
        event.preventDefault()
        firstElement.focus()
      }
    }
  }

  /**
   * Restore focus to a previously focused element
   */
  static restoreFocus(element: HTMLElement | null): void {
    if (element && typeof element.focus === 'function') {
      element.focus()
    }
  }
}

/**
 * Screen reader announcement utilities
 */
export class ScreenReaderAnnouncer {
  private static liveRegion: HTMLElement | null = null

  /**
   * Initialize the live region for announcements
   */
  static initialize(): void {
    if (this.liveRegion) return

    this.liveRegion = document.createElement('div')
    this.liveRegion.setAttribute('aria-live', ARIA_LIVE_PRIORITIES.POLITE)
    this.liveRegion.setAttribute('aria-atomic', 'true')
    this.liveRegion.className = 'sr-only'
    this.liveRegion.id = 'screen-reader-announcements'
    
    document.body.appendChild(this.liveRegion)
  }

  /**
   * Announce a message to screen readers
   */
  static announce(
    message: string, 
    priority: keyof typeof ARIA_LIVE_PRIORITIES = 'POLITE'
  ): void {
    this.initialize()
    
    if (!this.liveRegion) return

    // Update the priority if needed
    const priorityValue = ARIA_LIVE_PRIORITIES[priority]
    if (this.liveRegion.getAttribute('aria-live') !== priorityValue) {
      this.liveRegion.setAttribute('aria-live', priorityValue)
    }

    // Clear and set the message
    this.liveRegion.textContent = ''
    
    // Use a small delay to ensure screen readers pick up the change
    setTimeout(() => {
      if (this.liveRegion) {
        this.liveRegion.textContent = message
      }
    }, 100)

    // Clear the message after announcement
    setTimeout(() => {
      if (this.liveRegion) {
        this.liveRegion.textContent = ''
      }
    }, 1000)
  }

  /**
   * Announce form validation errors
   */
  static announceFormError(fieldName: string, errorMessage: string): void {
    this.announce(`${fieldName}: ${errorMessage}`, 'ASSERTIVE')
  }

  /**
   * Announce successful actions
   */
  static announceSuccess(message: string): void {
    this.announce(message, 'POLITE')
  }

  /**
   * Announce navigation changes
   */
  static announceNavigation(pageName: string): void {
    this.announce(`Navigated to ${pageName}`, 'POLITE')
  }
}

/**
 * High contrast detection and management
 */
export class HighContrastManager {
  /**
   * Check if high contrast mode is preferred by the system
   */
  static isSystemHighContrast(): boolean {
    if (typeof window === 'undefined') return false
    return window.matchMedia('(prefers-contrast: high)').matches
  }

  /**
   * Check if forced colors mode is active (Windows high contrast)
   */
  static isForcedColors(): boolean {
    if (typeof window === 'undefined') return false
    return window.matchMedia('(forced-colors: active)').matches
  }

  /**
   * Apply high contrast styles
   */
  static applyHighContrast(): void {
    document.documentElement.classList.add('high-contrast')
  }

  /**
   * Remove high contrast styles
   */
  static removeHighContrast(): void {
    document.documentElement.classList.remove('high-contrast')
  }

  /**
   * Listen for system high contrast changes
   */
  static onSystemHighContrastChange(callback: (isHighContrast: boolean) => void): () => void {
    if (typeof window === 'undefined') return () => {}

    const mediaQuery = window.matchMedia('(prefers-contrast: high)')
    const listener = (e: MediaQueryListEvent) => callback(e.matches)
    
    mediaQuery.addEventListener('change', listener)
    
    return () => mediaQuery.removeEventListener('change', listener)
  }
}

/**
 * Reduced motion detection and management
 */
export class ReducedMotionManager {
  /**
   * Check if reduced motion is preferred by the system
   */
  static isSystemReducedMotion(): boolean {
    if (typeof window === 'undefined') return false
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches
  }

  /**
   * Apply reduced motion styles
   */
  static applyReducedMotion(): void {
    document.documentElement.classList.add('reduce-motion')
  }

  /**
   * Remove reduced motion styles
   */
  static removeReducedMotion(): void {
    document.documentElement.classList.remove('reduce-motion')
  }

  /**
   * Listen for system reduced motion changes
   */
  static onSystemReducedMotionChange(callback: (isReducedMotion: boolean) => void): () => void {
    if (typeof window === 'undefined') return () => {}

    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
    const listener = (e: MediaQueryListEvent) => callback(e.matches)
    
    mediaQuery.addEventListener('change', listener)
    
    return () => mediaQuery.removeEventListener('change', listener)
  }
}

/**
 * Keyboard navigation helpers
 */
export class KeyboardNavigationHelper {
  /**
   * Handle arrow key navigation in a list
   */
  static handleArrowNavigation(
    event: KeyboardEvent,
    items: HTMLElement[],
    currentIndex: number,
    options: {
      loop?: boolean
      orientation?: 'horizontal' | 'vertical' | 'both'
    } = {}
  ): number {
    const { loop = true, orientation = 'vertical' } = options
    let newIndex = currentIndex

    switch (event.key) {
      case KEYBOARD_KEYS.ARROW_DOWN:
        if (orientation === 'vertical' || orientation === 'both') {
          event.preventDefault()
          newIndex = currentIndex + 1
          if (newIndex >= items.length) {
            newIndex = loop ? 0 : items.length - 1
          }
        }
        break
      case KEYBOARD_KEYS.ARROW_UP:
        if (orientation === 'vertical' || orientation === 'both') {
          event.preventDefault()
          newIndex = currentIndex - 1
          if (newIndex < 0) {
            newIndex = loop ? items.length - 1 : 0
          }
        }
        break
      case KEYBOARD_KEYS.ARROW_RIGHT:
        if (orientation === 'horizontal' || orientation === 'both') {
          event.preventDefault()
          newIndex = currentIndex + 1
          if (newIndex >= items.length) {
            newIndex = loop ? 0 : items.length - 1
          }
        }
        break
      case KEYBOARD_KEYS.ARROW_LEFT:
        if (orientation === 'horizontal' || orientation === 'both') {
          event.preventDefault()
          newIndex = currentIndex - 1
          if (newIndex < 0) {
            newIndex = loop ? items.length - 1 : 0
          }
        }
        break
      case KEYBOARD_KEYS.HOME:
        event.preventDefault()
        newIndex = 0
        break
      case KEYBOARD_KEYS.END:
        event.preventDefault()
        newIndex = items.length - 1
        break
    }

    return newIndex
  }

  /**
   * Set up roving tabindex for a list of items
   */
  static setupRovingTabIndex(items: HTMLElement[], activeIndex: number = 0): void {
    items.forEach((item, index) => {
      item.tabIndex = index === activeIndex ? 0 : -1
    })
  }

  /**
   * Update roving tabindex when focus changes
   */
  static updateRovingTabIndex(items: HTMLElement[], newActiveIndex: number): void {
    items.forEach((item, index) => {
      item.tabIndex = index === newActiveIndex ? 0 : -1
    })
    
    if (items[newActiveIndex]) {
      items[newActiveIndex].focus()
    }
  }
}

/**
 * Form accessibility helpers
 */
export class FormAccessibilityHelper {
  /**
   * Associate form field with error message
   */
  static associateFieldWithError(
    fieldId: string,
    errorId: string,
    errorMessage: string
  ): void {
    const field = document.getElementById(fieldId)
    const errorElement = document.getElementById(errorId)
    
    if (field && errorElement) {
      field.setAttribute('aria-invalid', 'true')
      field.setAttribute('aria-describedby', errorId)
      errorElement.textContent = errorMessage
      
      // Announce the error
      ScreenReaderAnnouncer.announceFormError(
        field.getAttribute('aria-label') || field.getAttribute('name') || 'Field',
        errorMessage
      )
    }
  }

  /**
   * Clear field error state
   */
  static clearFieldError(fieldId: string, errorId: string): void {
    const field = document.getElementById(fieldId)
    const errorElement = document.getElementById(errorId)
    
    if (field) {
      field.setAttribute('aria-invalid', 'false')
      field.removeAttribute('aria-describedby')
    }
    
    if (errorElement) {
      errorElement.textContent = ''
    }
  }

  /**
   * Generate unique IDs for form field associations
   */
  static generateFieldIds(baseName: string): {
    fieldId: string
    labelId: string
    errorId: string
    descriptionId: string
  } {
    const timestamp = Date.now()
    return {
      fieldId: `${baseName}-field-${timestamp}`,
      labelId: `${baseName}-label-${timestamp}`,
      errorId: `${baseName}-error-${timestamp}`,
      descriptionId: `${baseName}-description-${timestamp}`,
    }
  }
}

/**
 * Initialize accessibility features
 */
export function initializeAccessibility(): void {
  // Initialize screen reader announcements
  ScreenReaderAnnouncer.initialize()
  
  // Apply system preferences
  if (HighContrastManager.isSystemHighContrast()) {
    HighContrastManager.applyHighContrast()
  }
  
  if (ReducedMotionManager.isSystemReducedMotion()) {
    ReducedMotionManager.applyReducedMotion()
  }
  
  // Set up global keyboard event listeners for accessibility
  document.addEventListener('keydown', (event) => {
    // Global escape key handler
    if (event.key === KEYBOARD_KEYS.ESCAPE) {
      // Close any open modals, dropdowns, etc.
      const openModals = document.querySelectorAll('[data-modal-open="true"]')
      openModals.forEach(modal => {
        const closeButton = modal.querySelector('[data-close-modal]') as HTMLElement
        if (closeButton) {
          closeButton.click()
        }
      })
    }
  })
}