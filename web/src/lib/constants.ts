/**
 * Design System Constants
 * Netflix-inspired design tokens and constants for consistent theming
 */

// Theme modes
export const THEME_MODES = {
  LIGHT: 'light',
  DARK: 'dark',
  SYSTEM: 'system',
} as const

export type ThemeMode = typeof THEME_MODES[keyof typeof THEME_MODES]

// Netflix-inspired color palette
export const NETFLIX_COLORS = {
  RED: 'hsl(0, 100%, 50%)',
  DARK_RED: 'hsl(0, 100%, 45%)',
  BLACK: 'hsl(0, 0%, 9%)',
  DARK_GRAY: 'hsl(0, 0%, 14%)',
  GRAY: 'hsl(0, 0%, 20%)',
  LIGHT_GRAY: 'hsl(0, 0%, 45%)',
  WHITE: 'hsl(0, 0%, 98%)',
} as const

// Spacing scale
export const SPACING = {
  XS: '0.25rem',    // 4px
  SM: '0.5rem',     // 8px
  MD: '1rem',       // 16px
  LG: '1.5rem',     // 24px
  XL: '2rem',       // 32px
  '2XL': '3rem',    // 48px
  '3XL': '4rem',    // 64px
} as const

// Typography scale
export const TYPOGRAPHY = {
  FONT_SIZES: {
    XS: '0.75rem',    // 12px
    SM: '0.875rem',   // 14px
    BASE: '1rem',     // 16px
    LG: '1.125rem',   // 18px
    XL: '1.25rem',    // 20px
    '2XL': '1.5rem',  // 24px
    '3XL': '1.875rem', // 30px
    '4XL': '2.25rem', // 36px
  },
  FONT_WEIGHTS: {
    NORMAL: '400',
    MEDIUM: '500',
    SEMIBOLD: '600',
    BOLD: '700',
  },
  LINE_HEIGHTS: {
    TIGHT: '1.25',
    NORMAL: '1.5',
    RELAXED: '1.75',
  },
} as const

// Border radius scale
export const BORDER_RADIUS = {
  NONE: '0',
  SM: '0.125rem',   // 2px
  DEFAULT: '0.25rem', // 4px
  MD: '0.375rem',   // 6px
  LG: '0.5rem',     // 8px
  XL: '0.75rem',    // 12px
  '2XL': '1rem',    // 16px
  FULL: '9999px',
} as const

// Shadow scale
export const SHADOWS = {
  SM: '0 1px 2px 0 rgb(0 0 0 / 0.05)',
  DEFAULT: '0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1)',
  MD: '0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1)',
  LG: '0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1)',
  XL: '0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1)',
} as const

// Breakpoints
export const BREAKPOINTS = {
  SM: '640px',
  MD: '768px',
  LG: '1024px',
  XL: '1280px',
  '2XL': '1536px',
} as const

// Z-index scale
export const Z_INDEX = {
  DROPDOWN: 1000,
  STICKY: 1020,
  FIXED: 1030,
  MODAL_BACKDROP: 1040,
  MODAL: 1050,
  POPOVER: 1060,
  TOOLTIP: 1070,
  TOAST: 1080,
} as const

// Animation durations
export const ANIMATION = {
  DURATION: {
    FAST: '150ms',
    DEFAULT: '200ms',
    SLOW: '300ms',
  },
  EASING: {
    DEFAULT: 'cubic-bezier(0.4, 0, 0.2, 1)',
    IN: 'cubic-bezier(0.4, 0, 1, 1)',
    OUT: 'cubic-bezier(0, 0, 0.2, 1)',
    IN_OUT: 'cubic-bezier(0.4, 0, 0.2, 1)',
  },
} as const

// Component sizes
export const COMPONENT_SIZES = {
  SM: 'sm',
  DEFAULT: 'default',
  LG: 'lg',
} as const

export type ComponentSize = typeof COMPONENT_SIZES[keyof typeof COMPONENT_SIZES]

// Storage keys
export const STORAGE_KEYS = {
  THEME: 'crowdsec-manager-theme',
  SIDEBAR_COLLAPSED: 'crowdsec-manager-sidebar-collapsed',
  ACCESSIBILITY_PREFERENCES: 'crowdsec-manager-accessibility',
} as const