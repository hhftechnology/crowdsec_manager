import React from 'react'

/**
 * Performance optimization utilities for smooth animations and transitions
 */

// Debounce utility for performance-critical operations
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number,
  immediate?: boolean
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout | null = null
  
  return function executedFunction(...args: Parameters<T>) {
    const later = () => {
      timeout = null
      if (!immediate) func(...args)
    }
    
    const callNow = immediate && !timeout
    
    if (timeout) clearTimeout(timeout)
    timeout = setTimeout(later, wait)
    
    if (callNow) func(...args)
  }
}

// Throttle utility for scroll and resize events
export function throttle<T extends (...args: any[]) => any>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean
  
  return function executedFunction(...args: Parameters<T>) {
    if (!inThrottle) {
      func.apply(this, args)
      inThrottle = true
      setTimeout(() => inThrottle = false, limit)
    }
  }
}

// Request animation frame utility for smooth animations
export function rafThrottle<T extends (...args: any[]) => any>(
  func: T
): (...args: Parameters<T>) => void {
  let rafId: number | null = null
  
  return function executedFunction(...args: Parameters<T>) {
    if (rafId) return
    
    rafId = requestAnimationFrame(() => {
      func.apply(this, args)
      rafId = null
    })
  }
}

// Preload critical resources
export function preloadResource(href: string, as: string, type?: string): void {
  const link = document.createElement('link')
  link.rel = 'preload'
  link.href = href
  link.as = as
  if (type) link.type = type
  document.head.appendChild(link)
}

// Lazy load images with intersection observer
export function createImageObserver(
  callback: (entry: IntersectionObserverEntry) => void,
  options?: IntersectionObserverInit
): IntersectionObserver {
  const defaultOptions: IntersectionObserverInit = {
    root: null,
    rootMargin: '50px',
    threshold: 0.1,
    ...options
  }
  
  return new IntersectionObserver((entries) => {
    entries.forEach(callback)
  }, defaultOptions)
}

// Optimize bundle loading with dynamic imports
export function createLazyComponent<T extends React.ComponentType<any>>(
  importFunc: () => Promise<{ default: T }>,
  fallback?: React.ComponentType
) {
  return React.lazy(() => 
    importFunc().catch(() => ({
      default: fallback || (() => React.createElement('div', null, 'Failed to load component'))
    }))
  )
}

// Performance monitoring utilities
export class PerformanceMonitor {
  private static marks: Map<string, number> = new Map()
  
  static mark(name: string): void {
    if (typeof performance !== 'undefined' && performance.mark) {
      performance.mark(name)
      this.marks.set(name, performance.now())
    }
  }
  
  static measure(name: string, startMark: string, endMark?: string): number | null {
    if (typeof performance !== 'undefined' && performance.measure) {
      try {
        performance.measure(name, startMark, endMark)
        const measure = performance.getEntriesByName(name, 'measure')[0]
        return measure ? measure.duration : null
      } catch (error) {
        console.warn('Performance measurement failed:', error)
        return null
      }
    }
    
    // Fallback for environments without performance API
    const startTime = this.marks.get(startMark)
    const endTime = endMark ? this.marks.get(endMark) : performance.now()
    
    if (startTime && endTime) {
      return endTime - startTime
    }
    
    return null
  }
  
  static clearMarks(): void {
    if (typeof performance !== 'undefined' && performance.clearMarks) {
      performance.clearMarks()
    }
    this.marks.clear()
  }
}

// Memory usage monitoring (development only)
export function logMemoryUsage(label: string): void {
  if (process.env.NODE_ENV === 'development' && 'memory' in performance) {
    const memory = (performance as any).memory
    console.log(`${label} - Memory Usage:`, {
      used: `${Math.round(memory.usedJSHeapSize / 1024 / 1024)} MB`,
      total: `${Math.round(memory.totalJSHeapSize / 1024 / 1024)} MB`,
      limit: `${Math.round(memory.jsHeapSizeLimit / 1024 / 1024)} MB`
    })
  }
}

// Optimize CSS animations with will-change
export function optimizeForAnimation(element: HTMLElement, properties: string[]): void {
  element.style.willChange = properties.join(', ')
  
  // Clean up after animation
  const cleanup = () => {
    element.style.willChange = 'auto'
    element.removeEventListener('animationend', cleanup)
    element.removeEventListener('transitionend', cleanup)
  }
  
  element.addEventListener('animationend', cleanup)
  element.addEventListener('transitionend', cleanup)
}