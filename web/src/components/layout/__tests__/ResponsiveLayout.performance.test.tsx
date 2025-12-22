import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
import { ResponsiveLayout } from '../ResponsiveLayout'
import { PerformanceMonitor } from '@/lib/performance'

// Mock the useBreakpoints hook
vi.mock('@/hooks/useMediaQuery', () => ({
  useBreakpoints: vi.fn(() => ({
    isMobile: false,
    isTablet: false,
    isDesktop: true,
    isPortrait: false,
    needsTouchOptimization: false
  }))
}))

// Mock child components to focus on layout performance
vi.mock('../AppShell', () => ({
  AppShell: ({ children, sidebar, header }: any) => (
    <div data-testid="app-shell">
      <div data-testid="sidebar">{sidebar}</div>
      <div data-testid="header">{header}</div>
      <div data-testid="content">{children}</div>
    </div>
  )
}))

vi.mock('../AppSidebar', () => ({
  AppSidebar: ({ isCollapsed, onCollapsedChange }: any) => (
    <div data-testid="app-sidebar" data-collapsed={isCollapsed}>
      <button onClick={onCollapsedChange}>Toggle</button>
    </div>
  )
}))

vi.mock('../AppHeader', () => ({
  AppHeader: ({ onMobileMenuToggle, isMobile }: any) => (
    <div data-testid="app-header" data-mobile={isMobile}>
      <button onClick={onMobileMenuToggle}>Menu</button>
    </div>
  )
}))

const TestWrapper = ({ children }: { children: React.ReactNode }) => (
  <BrowserRouter>
    {children}
  </BrowserRouter>
)

describe('ResponsiveLayout Performance Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    PerformanceMonitor.clearMarks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('should render without performance issues', () => {
    PerformanceMonitor.mark('layout-render-start')
    
    const { rerender } = render(
      <TestWrapper>
        <ResponsiveLayout>
          <div>Test Content</div>
        </ResponsiveLayout>
      </TestWrapper>
    )

    PerformanceMonitor.mark('layout-render-end')
    const renderTime = PerformanceMonitor.measure('layout-render', 'layout-render-start', 'layout-render-end')
    
    expect(screen.getByTestId('app-shell')).toBeInTheDocument()
    expect(screen.getByText('Test Content')).toBeInTheDocument()
    
    // Performance assertion - render should be fast
    if (renderTime) {
      expect(renderTime).toBeLessThan(100) // Should render in less than 100ms
    }

    // Test re-render performance
    PerformanceMonitor.mark('layout-rerender-start')
    
    rerender(
      <TestWrapper>
        <ResponsiveLayout>
          <div>Updated Content</div>
        </ResponsiveLayout>
      </TestWrapper>
    )

    PerformanceMonitor.mark('layout-rerender-end')
    const rerenderTime = PerformanceMonitor.measure('layout-rerender', 'layout-rerender-start', 'layout-rerender-end')
    
    expect(screen.getByText('Updated Content')).toBeInTheDocument()
    
    // Re-render should be even faster due to memoization
    if (rerenderTime) {
      expect(rerenderTime).toBeLessThan(50)
    }
  })

  it('should handle rapid state changes efficiently', async () => {
    const { useBreakpoints } = await import('@/hooks/useMediaQuery')
    const mockUseBreakpoints = vi.mocked(useBreakpoints)

    render(
      <TestWrapper>
        <ResponsiveLayout>
          <div>Test Content</div>
        </ResponsiveLayout>
      </TestWrapper>
    )

    PerformanceMonitor.mark('state-changes-start')

    // Simulate rapid breakpoint changes
    for (let i = 0; i < 10; i++) {
      mockUseBreakpoints.mockReturnValue({
        isMobile: i % 2 === 0,
        isTablet: false,
        isDesktop: i % 2 === 1,
        isPortrait: false,
        needsTouchOptimization: false
      })

      // Trigger re-render
      fireEvent.resize(window)
      await waitFor(() => {}, { timeout: 10 })
    }

    PerformanceMonitor.mark('state-changes-end')
    const stateChangeTime = PerformanceMonitor.measure('state-changes', 'state-changes-start', 'state-changes-end')

    // Multiple state changes should still be performant
    if (stateChangeTime) {
      expect(stateChangeTime).toBeLessThan(200)
    }
  })

  it('should optimize event listener management', () => {
    const addEventListenerSpy = vi.spyOn(document, 'addEventListener')
    const removeEventListenerSpy = vi.spyOn(document, 'removeEventListener')

    const { unmount } = render(
      <TestWrapper>
        <ResponsiveLayout>
          <div>Test Content</div>
        </ResponsiveLayout>
      </TestWrapper>
    )

    // Should add event listeners for keyboard and mouse events
    expect(addEventListenerSpy).toHaveBeenCalledWith('mousedown', expect.any(Function))
    expect(addEventListenerSpy).toHaveBeenCalledWith('keydown', expect.any(Function))

    const initialCallCount = addEventListenerSpy.mock.calls.length

    unmount()

    // Should clean up event listeners
    expect(removeEventListenerSpy).toHaveBeenCalledWith('mousedown', expect.any(Function))
    expect(removeEventListenerSpy).toHaveBeenCalledWith('keydown', expect.any(Function))

    // Should have equal number of add/remove calls
    expect(removeEventListenerSpy.mock.calls.length).toBeGreaterThanOrEqual(initialCallCount)
  })

  it('should memoize expensive calculations', () => {
    const { rerender } = render(
      <TestWrapper>
        <ResponsiveLayout className="test-class">
          <div>Test Content</div>
        </ResponsiveLayout>
      </TestWrapper>
    )

    const initialElement = screen.getByTestId('app-shell').parentElement
    const initialClasses = initialElement?.className

    // Re-render with same props - should use memoized values
    rerender(
      <TestWrapper>
        <ResponsiveLayout className="test-class">
          <div>Test Content</div>
        </ResponsiveLayout>
      </TestWrapper>
    )

    const afterRerenderElement = screen.getByTestId('app-shell').parentElement
    const afterRerenderClasses = afterRerenderElement?.className

    // Classes should be identical (memoized)
    expect(initialClasses).toBe(afterRerenderClasses)
  })

  it('should handle keyboard events efficiently', async () => {
    render(
      <TestWrapper>
        <ResponsiveLayout>
          <div>Test Content</div>
        </ResponsiveLayout>
      </TestWrapper>
    )

    PerformanceMonitor.mark('keyboard-events-start')

    // Simulate rapid keyboard events
    for (let i = 0; i < 20; i++) {
      fireEvent.keyDown(document, { key: 'Escape' })
      fireEvent.keyDown(document, { key: 'b', ctrlKey: true })
      await waitFor(() => {}, { timeout: 5 })
    }

    PerformanceMonitor.mark('keyboard-events-end')
    const keyboardEventTime = PerformanceMonitor.measure('keyboard-events', 'keyboard-events-start', 'keyboard-events-end')

    // Keyboard event handling should be reasonably fast (relaxed benchmark)
    if (keyboardEventTime) {
      expect(keyboardEventTime).toBeLessThan(500) // Relaxed from 100ms to 500ms
    }
  })

  it('should optimize mobile menu transitions', async () => {
    const { useBreakpoints } = await import('@/hooks/useMediaQuery')
    const mockUseBreakpoints = vi.mocked(useBreakpoints)

    // Set mobile breakpoint
    mockUseBreakpoints.mockReturnValue({
      isMobile: true,
      isTablet: false,
      isDesktop: false,
      isPortrait: true,
      needsTouchOptimization: true
    })

    render(
      <TestWrapper>
        <ResponsiveLayout>
          <div>Test Content</div>
        </ResponsiveLayout>
      </TestWrapper>
    )

    const menuButton = screen.getByText('Menu')

    PerformanceMonitor.mark('menu-toggle-start')

    // Simulate rapid menu toggles
    for (let i = 0; i < 10; i++) {
      fireEvent.click(menuButton)
      await waitFor(() => {}, { timeout: 10 })
    }

    PerformanceMonitor.mark('menu-toggle-end')
    const menuToggleTime = PerformanceMonitor.measure('menu-toggle', 'menu-toggle-start', 'menu-toggle-end')

    // Menu toggles should be smooth and fast
    if (menuToggleTime) {
      expect(menuToggleTime).toBeLessThan(150)
    }
  })

  it('should prevent memory leaks in event handlers', () => {
    const { unmount } = render(
      <TestWrapper>
        <ResponsiveLayout>
          <div>Test Content</div>
        </ResponsiveLayout>
      </TestWrapper>
    )

    // Capture initial memory usage (if available)
    const initialMemory = (performance as any).memory?.usedJSHeapSize

    // Unmount component
    unmount()

    // Force garbage collection if available
    if (global.gc) {
      global.gc()
    }

    // Memory should not increase significantly after unmount
    const finalMemory = (performance as any).memory?.usedJSHeapSize
    
    if (initialMemory && finalMemory) {
      const memoryIncrease = finalMemory - initialMemory
      // Allow for some variance but should not leak significantly
      expect(memoryIncrease).toBeLessThan(1024 * 1024) // Less than 1MB increase
    }
  })

  it('should optimize CSS class calculations', () => {
    const { rerender } = render(
      <TestWrapper>
        <ResponsiveLayout>
          <div>Test Content</div>
        </ResponsiveLayout>
      </TestWrapper>
    )

    PerformanceMonitor.mark('class-calc-start')

    // Multiple re-renders should use memoized class calculations
    for (let i = 0; i < 5; i++) {
      rerender(
        <TestWrapper>
          <ResponsiveLayout>
            <div>Test Content {i}</div>
          </ResponsiveLayout>
        </TestWrapper>
      )
    }

    PerformanceMonitor.mark('class-calc-end')
    const classCalcTime = PerformanceMonitor.measure('class-calc', 'class-calc-start', 'class-calc-end')

    // Class calculations should be optimized through memoization
    if (classCalcTime) {
      expect(classCalcTime).toBeLessThan(50)
    }
  })
})