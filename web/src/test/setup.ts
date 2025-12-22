import '@testing-library/jest-dom'

// Global mock for ResizeObserver (required for Radix UI components)
global.ResizeObserver = class ResizeObserver {
  constructor(callback: ResizeObserverCallback) {
    this.callback = callback
  }
  
  private callback: ResizeObserverCallback
  
  observe() {
    // Mock implementation - do nothing
  }
  
  unobserve() {
    // Mock implementation - do nothing
  }
  
  disconnect() {
    // Mock implementation - do nothing
  }
}

// Global mock for window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => {},
  }),
})

// Global mock for localStorage
Object.defineProperty(window, 'localStorage', {
  value: {
    getItem: () => null,
    setItem: () => {},
    removeItem: () => {},
    clear: () => {},
  },
  writable: true,
})

// Mock IntersectionObserver (also used by some Radix components)
global.IntersectionObserver = class IntersectionObserver {
  constructor(callback: IntersectionObserverCallback) {
    this.callback = callback
  }
  
  private callback: IntersectionObserverCallback
  
  observe() {
    // Mock implementation - do nothing
  }
  
  unobserve() {
    // Mock implementation - do nothing
  }
  
  disconnect() {
    // Mock implementation - do nothing
  }
}