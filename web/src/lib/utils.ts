import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"
import { type ComponentSize, COMPONENT_SIZES } from "./constants"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}

export function formatDate(date: string | Date): string {
  return new Date(date).toLocaleString()
}

/**
 * Design system utility functions
 */

/**
 * Get component size variant classes
 */
export function getComponentSizeClasses(size: ComponentSize, type: 'button' | 'input' | 'card' = 'button') {
  const sizeMap = {
    button: {
      [COMPONENT_SIZES.SM]: 'h-8 px-3 text-sm',
      [COMPONENT_SIZES.DEFAULT]: 'h-10 px-4 text-sm',
      [COMPONENT_SIZES.LG]: 'h-12 px-6 text-base',
    },
    input: {
      [COMPONENT_SIZES.SM]: 'h-8 px-3 text-sm',
      [COMPONENT_SIZES.DEFAULT]: 'h-10 px-3 text-sm',
      [COMPONENT_SIZES.LG]: 'h-12 px-4 text-base',
    },
    card: {
      [COMPONENT_SIZES.SM]: 'p-4',
      [COMPONENT_SIZES.DEFAULT]: 'p-6',
      [COMPONENT_SIZES.LG]: 'p-8',
    },
  }
  
  return sizeMap[type][size] || sizeMap[type][COMPONENT_SIZES.DEFAULT]
}

/**
 * Generate responsive classes for different breakpoints
 */
export function responsive(classes: {
  base?: string
  sm?: string
  md?: string
  lg?: string
  xl?: string
  '2xl'?: string
}) {
  const responsiveClasses = []
  
  if (classes.base) responsiveClasses.push(classes.base)
  if (classes.sm) responsiveClasses.push(`sm:${classes.sm}`)
  if (classes.md) responsiveClasses.push(`md:${classes.md}`)
  if (classes.lg) responsiveClasses.push(`lg:${classes.lg}`)
  if (classes.xl) responsiveClasses.push(`xl:${classes.xl}`)
  if (classes['2xl']) responsiveClasses.push(`2xl:${classes['2xl']}`)
  
  return responsiveClasses.join(' ')
}

/**
 * Create focus ring classes with Netflix theme
 */
export function focusRing(variant: 'default' | 'destructive' | 'netflix' = 'default') {
  const variants = {
    default: 'focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
    destructive: 'focus-visible:ring-2 focus-visible:ring-destructive focus-visible:ring-offset-2',
    netflix: 'focus-visible:ring-2 focus-visible:ring-netflix-red focus-visible:ring-offset-2',
  }
  
  return variants[variant]
}

/**
 * Create transition classes
 */
export function transition(properties: string[] = ['all'], duration: 'fast' | 'default' | 'slow' = 'default') {
  const durationMap = {
    fast: 'duration-150',
    default: 'duration-200',
    slow: 'duration-300',
  }
  
  const propertyClasses = properties.map(prop => {
    if (prop === 'all') return 'transition-all'
    if (prop === 'colors') return 'transition-colors'
    if (prop === 'opacity') return 'transition-opacity'
    if (prop === 'shadow') return 'transition-shadow'
    if (prop === 'transform') return 'transition-transform'
    return `transition-${prop}`
  }).join(' ')
  
  return `${propertyClasses} ${durationMap[duration]} ease-in-out`
}

/**
 * Create Netflix-inspired gradient classes
 */
export function netflixGradient(direction: 'to-r' | 'to-l' | 'to-t' | 'to-b' = 'to-r') {
  return `bg-gradient-${direction} from-netflix-red to-netflix-dark-red`
}

/**
 * Validate and normalize component props
 */
export function validateComponentSize(size?: string): ComponentSize {
  if (size && Object.values(COMPONENT_SIZES).includes(size as ComponentSize)) {
    return size as ComponentSize
  }
  return COMPONENT_SIZES.DEFAULT
}

/**
 * Create accessible button classes
 */
export function accessibleButton(variant: 'default' | 'primary' | 'destructive' | 'ghost' = 'default') {
  const baseClasses = 'inline-flex items-center justify-center rounded-md font-medium transition-colors focus-visible:outline-none disabled:pointer-events-none disabled:opacity-50'
  
  const variants = {
    default: 'bg-secondary text-secondary-foreground hover:bg-secondary/80',
    primary: 'bg-primary text-primary-foreground hover:bg-primary/90',
    destructive: 'bg-destructive text-destructive-foreground hover:bg-destructive/90',
    ghost: 'hover:bg-accent hover:text-accent-foreground',
  }
  
  return cn(baseClasses, variants[variant], focusRing())
}
