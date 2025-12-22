/**
 * Accessibility components index
 * Exports all accessibility-related components and utilities
 */

export { AccessibilityProvider, useAccessibility } from './AccessibilityProvider'
export { AccessibilitySettings } from './AccessibilitySettings'
export { KeyboardShortcutsDialog } from './KeyboardShortcutsDialog'
export { SkipLinks } from './SkipLinks'
export { FocusTrap } from './FocusTrap'
export { LiveRegion } from './LiveRegion'

// Re-export accessibility utilities
export {
  FocusManager,
  ScreenReaderAnnouncer,
  HighContrastManager,
  ReducedMotionManager,
  KeyboardNavigationHelper,
  FormAccessibilityHelper,
  initializeAccessibility,
  DEFAULT_SKIP_LINKS,
  KEYBOARD_KEYS,
  ARIA_LIVE_PRIORITIES,
} from '@/lib/accessibility'

// Re-export accessibility hooks
export {
  useKeyboardNavigation,
  useFocusTrap,
  useRovingTabIndex,
  useScreenReader,
} from '@/hooks/useKeyboardNavigation'