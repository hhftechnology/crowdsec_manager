/**
 * Standardized component patterns and interfaces
 * Eliminates duplication and ensures consistent behavior across contexts
 */

import { ReactNode, ComponentType } from 'react'

// Base component interface that all standardized components should extend
export interface BaseComponentProps {
  className?: string
  children?: ReactNode
  'data-testid'?: string
}

// Status-related interfaces
export interface StatusVariant {
  variant: 'success' | 'warning' | 'error' | 'info' | 'neutral'
}

export interface StatusCardBaseProps extends BaseComponentProps, StatusVariant {
  title: string
  value: string | number
  description?: string
  icon?: ComponentType<{ className?: string }>
  loading?: boolean
  onClick?: () => void
}

export interface TrendData {
  value: number
  label: string
  direction: 'up' | 'down' | 'neutral'
}

// Layout-related interfaces
export interface LayoutComponentProps extends BaseComponentProps {
  isCollapsed?: boolean
  isMobile?: boolean
  onToggle?: () => void
}

export interface NavigationItem {
  id: string
  label: string
  href: string
  icon: ComponentType<{ className?: string }>
  badge?: string | number
  children?: NavigationItem[]
  permissions?: string[]
}

export interface NavigationSection {
  id: string
  title: string
  items: NavigationItem[]
}

// Data display interfaces
export interface ColumnDefinition<T> {
  id: string
  header: string
  accessorKey?: keyof T
  cell?: (item: T) => ReactNode
  sortable?: boolean
  filterable?: boolean
  width?: string
}

export interface PaginationState {
  page: number
  pageSize: number
  total: number
}

export interface SortingState {
  column: string
  direction: 'asc' | 'desc'
}

export interface FilteringState {
  column: string
  value: string
}

// Form-related interfaces
export interface FormFieldProps extends BaseComponentProps {
  label: string
  error?: string
  required?: boolean
  disabled?: boolean
  loading?: boolean
}

export interface ValidationRule {
  required?: boolean
  minLength?: number
  maxLength?: number
  pattern?: RegExp
  custom?: (value: any) => string | undefined
}

// Theme and accessibility interfaces
export interface ThemeConfig {
  mode: 'light' | 'dark' | 'system'
  resolvedMode: 'light' | 'dark'
  accessibility: AccessibilityPreferences
}

export interface AccessibilityPreferences {
  highContrast: boolean
  reducedMotion: boolean
  largeText: boolean
  screenReaderOptimized: boolean
}

// Loading and error state interfaces
export interface LoadingState {
  isLoading: boolean
  error?: string | null
  data?: any
}

export interface ErrorBoundaryProps extends BaseComponentProps {
  fallback?: ComponentType<{ error: Error; resetError: () => void }>
  onError?: (error: Error, errorInfo: any) => void
}

// Responsive behavior interfaces
export interface ResponsiveConfig {
  mobile: boolean
  tablet: boolean
  desktop: boolean
}

export interface BreakpointConfig {
  sm: string
  md: string
  lg: string
  xl: string
  '2xl': string
}

// Component composition patterns
export interface CompositeComponentProps extends BaseComponentProps {
  header?: ReactNode
  content?: ReactNode
  footer?: ReactNode
  sidebar?: ReactNode
}

// Event handler patterns
export interface StandardEventHandlers {
  onClick?: () => void
  onFocus?: () => void
  onBlur?: () => void
  onKeyDown?: (event: KeyboardEvent) => void
  onMouseEnter?: () => void
  onMouseLeave?: () => void
}

// Animation and transition interfaces
export interface AnimationConfig {
  duration: number
  easing: string
  delay?: number
}

export interface TransitionProps {
  show: boolean
  enter?: string
  enterFrom?: string
  enterTo?: string
  leave?: string
  leaveFrom?: string
  leaveTo?: string
}

// Utility type for component variants
export type ComponentVariant<T extends string> = {
  variant: T
}

// Utility type for component sizes
export type ComponentSize = 'sm' | 'md' | 'lg' | 'xl'

// Utility type for component states
export type ComponentState = 'idle' | 'loading' | 'success' | 'error'

// Pattern for consistent prop spreading
export interface SpreadableProps {
  [key: string]: any
}

// Pattern for ref forwarding
export interface ForwardRefProps<T = HTMLElement> {
  ref?: React.Ref<T>
}

// Pattern for polymorphic components
export interface PolymorphicProps<T extends React.ElementType = 'div'> {
  as?: T
}

// Utility functions for component patterns
export const createComponentVariants = <T extends Record<string, any>>(
  variants: T
): T => variants

export const createResponsiveProps = (
  mobile: any,
  tablet?: any,
  desktop?: any
) => ({
  mobile,
  tablet: tablet ?? mobile,
  desktop: desktop ?? tablet ?? mobile,
})

export const createAnimationConfig = (
  duration: number,
  easing: string = 'ease-in-out',
  delay: number = 0
): AnimationConfig => ({
  duration,
  easing,
  delay,
})

// Constants for consistent behavior
export const COMPONENT_SIZES: Record<ComponentSize, string> = {
  sm: 'sm',
  md: 'md', 
  lg: 'lg',
  xl: 'xl',
}

export const ANIMATION_DURATIONS = {
  fast: 150,
  normal: 300,
  slow: 500,
} as const

export const BREAKPOINTS: BreakpointConfig = {
  sm: '640px',
  md: '768px',
  lg: '1024px',
  xl: '1280px',
  '2xl': '1536px',
}

// Validation helpers
export const validateComponentProps = <T extends BaseComponentProps>(
  props: T,
  requiredProps: (keyof T)[]
): void => {
  requiredProps.forEach(prop => {
    if (props[prop] === undefined || props[prop] === null) {
      throw new Error(`Required prop '${String(prop)}' is missing`)
    }
  })
}

// Component factory pattern
export const createStandardComponent = <P extends BaseComponentProps>(
  displayName: string,
  defaultProps?: Partial<P>
) => {
  return (Component: ComponentType<P>) => {
    Component.displayName = displayName
    if (defaultProps) {
      Component.defaultProps = defaultProps
    }
    return Component
  }
}