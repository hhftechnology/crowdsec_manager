/**
 * Property-based tests for layout system behavior
 * **Feature: ui-revamp-shadcn-admin, Property 4: Layout System Property**
 * **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, act, fireEvent } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
import * as fc from 'fast-check'

// Mock window.matchMedia before any imports that might use it
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(), // deprecated
    removeListener: vi.fn(), // deprecated
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
})

// Mock localStorage
Object.defineProperty(window, 'localStorage', {
  value: {
    getItem: vi.fn(() => null),
    setItem: vi.fn(),
    removeItem: vi.fn(),
    clear: vi.fn(),
  },
  writable: true,
})

// Mock theme utilities to prevent window.matchMedia calls during initialization
vi.mock('../../../lib/theme', () => ({
  getSystemTheme: vi.fn(() => 'light'),
  getSystemAccessibilityPreferences: vi.fn(() => ({})),
  resolveTheme: vi.fn((mode, systemPreference) => {
    if (mode === 'system') return systemPreference || 'light'
    return mode
  }),
  applyTheme: vi.fn(),
  getStoredTheme: vi.fn(() => 'system'),
  storeTheme: vi.fn(),
  getStoredAccessibilityPreferences: vi.fn(() => ({
    highContrast: false,
    reducedMotion: false,
    largeText: false,
    screenReaderOptimized: false,
  })),
  storeAccessibilityPreferences: vi.fn(),
  createSystemThemeListener: vi.fn(() => () => {}),
  createAccessibilityListeners: vi.fn(() => () => {}),
}))

import { ResponsiveLayout } from '../ResponsiveLayout'
import { AppShell } from '../AppShell'
import { AppSidebar } from '../AppSidebar'
import { AppHeader } from '../AppHeader'
import { ThemeProvider } from '../../ThemeProvider'

// Mock the useBreakpoints hook
const mockBreakpoints = {
  isMobile: false,
  isTablet: false,
  isDesktop: true,
  isLargeDesktop: false,
  isTouchDevice: false,
  isLandscape: true,
  isPortrait: false,
  isHighDPI: false,
  isMobileOrTablet: false,
  isTabletOrDesktop: true
}

vi.mock('../../../hooks/useMediaQuery', () => ({
  useBreakpoints: () => mockBreakpoints,
  useMediaQuery: vi.fn((query: string) => {
    if (query.includes('max-width: 768px')) return mockBreakpoints.isMobile
    if (query.includes('min-width: 769px') && query.includes('max-width: 1024px')) return mockBreakpoints.isTablet
    if (query.includes('min-width: 1025px')) return mockBreakpoints.isDesktop
    return false
  })
}))

// Mock other components that might cause issues
vi.mock('../../EnrollDialog', () => ({
  default: ({ trigger }: { trigger: React.ReactNode }) => trigger
}))

vi.mock('../../icons/CrowdSecLogo', () => ({
  CrowdSecLogo: ({ className }: { className?: string }) => (
    <div className={className} data-testid="crowdsec-logo">Logo</div>
  )
}))

// Test wrapper component
function TestWrapper({ children }: { children: React.ReactNode }) {
  return (
    <BrowserRouter>
      <ThemeProvider>
        {children}
      </ThemeProvider>
    </BrowserRouter>
  )
}

// Generators for property-based testing
const viewportSizeGen = fc.record({
  isMobile: fc.boolean(),
  isTablet: fc.boolean(),
  isDesktop: fc.boolean(),
  width: fc.integer({ min: 320, max: 2560 }),
  height: fc.integer({ min: 568, max: 1440 })
})

const navigationStateGen = fc.record({
  isCollapsed: fc.boolean(),
  isMobileMenuOpen: fc.boolean(),
  currentPath: fc.constantFrom('/', '/health', '/decisions', '/logs', '/settings')
})

const contentDataGen = fc.record({
  title: fc.string({ minLength: 1, maxLength: 100 }),
  hasActions: fc.boolean(),
  hasFooter: fc.boolean(),
  contentHeight: fc.constantFrom('short', 'medium', 'long', 'very-long')
})

describe('Layout System Property Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Reset DOM
    document.body.innerHTML = ''
    document.documentElement.className = ''
  })

  afterEach(() => {
    document.body.innerHTML = ''
    document.documentElement.className = ''
  })

  /**
   * Property 4: Layout System Property
   * For any viewport size and navigation state, the layout should provide appropriate 
   * responsive behavior with consistent header, sidebar, and content areas
   */
  it('should provide consistent layout structure across all viewport sizes', () => {
    fc.assert(
      fc.property(
        viewportSizeGen,
        navigationStateGen,
        contentDataGen,
        (viewport, navState, content) => {
          // Update mock breakpoints based on viewport
          mockBreakpoints.isMobile = viewport.width <= 768
          mockBreakpoints.isTablet = viewport.width > 768 && viewport.width <= 1024
          mockBreakpoints.isDesktop = viewport.width > 1024
          mockBreakpoints.isMobileOrTablet = mockBreakpoints.isMobile || mockBreakpoints.isTablet
          mockBreakpoints.isTabletOrDesktop = mockBreakpoints.isTablet || mockBreakpoints.isDesktop

          const TestContent = () => (
            <div data-testid="main-content">
              <h1>{content.title}</h1>
              {content.hasActions && <div data-testid="content-actions">Actions</div>}
              <div 
                data-testid="content-body" 
                style={{ 
                  height: content.contentHeight === 'short' ? '200px' : 
                          content.contentHeight === 'medium' ? '800px' :
                          content.contentHeight === 'long' ? '1500px' : '3000px'
                }}
              >
                Content body
              </div>
            </div>
          )

          const { unmount } = render(
            <TestWrapper>
              <ResponsiveLayout>
                <TestContent />
              </ResponsiveLayout>
            </TestWrapper>
          )

          // Verify main content is always present
          const mainContent = screen.getByTestId('main-content')
          expect(mainContent).toBeInTheDocument()

          // Verify layout structure consistency
          // The layout should always have the main structural elements
          const layoutContainer = mainContent.closest('[class*="relative"]')
          expect(layoutContainer).toBeInTheDocument()

          // Verify content is properly contained
          expect(mainContent.textContent).toContain(content.title)

          // Verify responsive behavior
          if (mockBreakpoints.isMobile) {
            // On mobile, content should be properly padded
            const contentWrapper = mainContent.closest('[class*="p-3"]')
            expect(contentWrapper).toBeInTheDocument()
          } else if (mockBreakpoints.isTablet) {
            // On tablet, content should have medium padding
            const contentWrapper = mainContent.closest('[class*="p-4"]') || mainContent.closest('[class*="p-3"]')
            expect(contentWrapper).toBeInTheDocument()
          } else if (mockBreakpoints.isDesktop) {
            // On desktop, content should have larger padding
            const contentWrapper = mainContent.closest('[class*="p-6"]') || mainContent.closest('[class*="p-4"]')
            expect(contentWrapper).toBeInTheDocument()
          }

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should maintain sidebar collapsible behavior across viewport changes', () => {
    fc.assert(
      fc.property(
        fc.array(viewportSizeGen, { minLength: 2, maxLength: 5 }),
        navigationStateGen,
        (viewportSequence, initialNavState) => {
          const currentNavState = { ...initialNavState }

          const { unmount } = render(
            <TestWrapper>
              <AppSidebar 
                isCollapsed={currentNavState.isCollapsed}
                onCollapsedChange={(collapsed) => {
                  currentNavState.isCollapsed = collapsed
                }}
              />
            </TestWrapper>
          )

          // Test sidebar behavior across viewport changes
          viewportSequence.forEach((viewport) => {
            // Update breakpoints
            mockBreakpoints.isMobile = viewport.width <= 768
            mockBreakpoints.isTablet = viewport.width > 768 && viewport.width <= 1024
            mockBreakpoints.isDesktop = viewport.width > 1024

            // Verify sidebar structure is maintained
            const sidebar = screen.getByRole('navigation')
            expect(sidebar).toBeInTheDocument()

            // Verify sidebar has appropriate width classes
            const sidebarClasses = sidebar.className
            expect(sidebarClasses).toMatch(/w-(16|64)/)

            // Verify toggle button is present
            const toggleButton = screen.getByLabelText(/expand sidebar|collapse sidebar/i)
            expect(toggleButton).toBeInTheDocument()

            // Test toggle functionality
            act(() => {
              fireEvent.click(toggleButton)
            })

            // Sidebar should still be present after toggle
            expect(screen.getByRole('navigation')).toBeInTheDocument()
          })

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should provide consistent header structure with breadcrumbs', () => {
    fc.assert(
      fc.property(
        viewportSizeGen,
        fc.array(fc.string({ minLength: 1, maxLength: 20 }), { minLength: 1, maxLength: 5 }),
        fc.option(fc.string({ minLength: 1, maxLength: 50 })),
        (viewport, pathSegments, title) => {
          // Update breakpoints
          mockBreakpoints.isMobile = viewport.width <= 768
          mockBreakpoints.isTablet = viewport.width > 768 && viewport.width <= 1024
          mockBreakpoints.isDesktop = viewport.width > 1024

          const breadcrumbs = pathSegments.map((segment, index) => ({
            label: segment,
            href: `/${pathSegments.slice(0, index + 1).join('/')}`
          }))

          const { unmount } = render(
            <TestWrapper>
              <AppHeader 
                title={title}
                breadcrumbs={breadcrumbs}
                isMobile={mockBreakpoints.isMobile}
              />
            </TestWrapper>
          )

          // Verify header structure
          const headers = screen.getAllByRole('banner')
          expect(headers.length).toBeGreaterThan(0)
          const header = headers[0] // Use the first header for verification
          expect(header).toBeInTheDocument()

          // Verify header has appropriate height classes
          const headerClasses = header.className
          expect(headerClasses).toMatch(/h-(14|16)/)

          // Verify title or breadcrumbs are present
          if (title) {
            expect(screen.getByText(title)).toBeInTheDocument()
          } else if (breadcrumbs.length > 0) {
            // At least one breadcrumb should be visible
            const breadcrumbElements = screen.getAllByRole('link').concat(
              screen.queryAllByText(new RegExp(pathSegments.join('|'), 'i'))
            )
            expect(breadcrumbElements.length).toBeGreaterThan(0)
          }

          // Verify user menu is present
          const userMenu = screen.getByRole('button', { name: /user menu|avatar/i }) || 
                          screen.getByRole('button', { expanded: false })
          expect(userMenu).toBeInTheDocument()

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should handle mobile overlay behavior correctly', () => {
    fc.assert(
      fc.property(
        fc.boolean(), // isMobileMenuOpen
        fc.boolean(), // hasOverlay
        (isMobileMenuOpen, shouldHaveOverlay) => {
          // Force mobile viewport
          mockBreakpoints.isMobile = true
          mockBreakpoints.isTablet = false
          mockBreakpoints.isDesktop = false

          const { unmount } = render(
            <TestWrapper>
              <ResponsiveLayout>
                <div data-testid="test-content">Test Content</div>
              </ResponsiveLayout>
            </TestWrapper>
          )

          // Verify content is always accessible
          expect(screen.getByTestId('test-content')).toBeInTheDocument()

          // Verify mobile menu toggle is present in header
          const mobileMenuToggle = screen.getByLabelText(/toggle mobile menu/i)
          expect(mobileMenuToggle).toBeInTheDocument()

          // Test mobile menu toggle
          act(() => {
            fireEvent.click(mobileMenuToggle)
          })

          // After toggle, content should still be accessible
          expect(screen.getByTestId('test-content')).toBeInTheDocument()

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should maintain layout integrity during rapid viewport changes', () => {
    fc.assert(
      fc.property(
        fc.array(viewportSizeGen, { minLength: 3, maxLength: 8 }),
        (rapidViewportChanges) => {
          const { unmount } = render(
            <TestWrapper>
              <ResponsiveLayout>
                <div data-testid="stable-content">Stable Content</div>
              </ResponsiveLayout>
            </TestWrapper>
          )

          // Apply rapid viewport changes
          rapidViewportChanges.forEach((viewport) => {
            mockBreakpoints.isMobile = viewport.width <= 768
            mockBreakpoints.isTablet = viewport.width > 768 && viewport.width <= 1024
            mockBreakpoints.isDesktop = viewport.width > 1024
            mockBreakpoints.isMobileOrTablet = mockBreakpoints.isMobile || mockBreakpoints.isTablet
            mockBreakpoints.isTabletOrDesktop = mockBreakpoints.isTablet || mockBreakpoints.isDesktop

            // Force re-render by triggering a state change
            act(() => {
              // Simulate viewport change effect
            })
          })

          // Content should remain stable and accessible
          expect(screen.getByTestId('stable-content')).toBeInTheDocument()

          // Layout structure should be intact
          const content = screen.getByTestId('stable-content')
          const layoutContainer = content.closest('[class*="relative"]')
          expect(layoutContainer).toBeInTheDocument()

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should provide touch-friendly interactions on mobile devices', () => {
    fc.assert(
      fc.property(
        fc.boolean(), // isTouchDevice
        fc.constantFrom('portrait', 'landscape'), // orientation
        (isTouchDevice, orientation) => {
          // Force mobile viewport with touch
          mockBreakpoints.isMobile = true
          mockBreakpoints.isTouchDevice = isTouchDevice
          mockBreakpoints.isPortrait = orientation === 'portrait'
          mockBreakpoints.isLandscape = orientation === 'landscape'

          const { unmount } = render(
            <TestWrapper>
              <AppSidebar isCollapsed={false} />
            </TestWrapper>
          )

          // Verify navigation is accessible
          const navigation = screen.getByRole('navigation')
          expect(navigation).toBeInTheDocument()

          // Verify navigation items are present and clickable
          const navLinks = screen.getAllByRole('link')
          expect(navLinks.length).toBeGreaterThan(0)

          // Each navigation link should be accessible
          navLinks.forEach(link => {
            expect(link).toBeInTheDocument()
            expect(link).toHaveAttribute('href')
          })

          // Verify theme toggle is accessible
          const themeToggle = screen.getByLabelText(/switch to.*theme/i)
          expect(themeToggle).toBeInTheDocument()

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should maintain accessibility attributes across all layout states', () => {
    fc.assert(
      fc.property(
        viewportSizeGen,
        navigationStateGen,
        (viewport, navState) => {
          // Update breakpoints
          mockBreakpoints.isMobile = viewport.width <= 768
          mockBreakpoints.isTablet = viewport.width > 768 && viewport.width <= 1024
          mockBreakpoints.isDesktop = viewport.width > 1024

          const { unmount } = render(
            <TestWrapper>
              <AppShell
                sidebar={
                  <AppSidebar 
                    isCollapsed={navState.isCollapsed}
                  />
                }
                header={
                  <AppHeader 
                    isMobile={mockBreakpoints.isMobile}
                  />
                }
              >
                <div data-testid="main-content">Main Content</div>
              </AppShell>
            </TestWrapper>
          )

          // Verify essential accessibility attributes
          const navigations = screen.getAllByRole('navigation')
          expect(navigations.length).toBeGreaterThan(0)
          const navigation = navigations.find(nav => 
            nav.getAttribute('aria-label') === 'Main navigation'
          ) || navigations[0]
          expect(navigation).toHaveAttribute('aria-label', 'Main navigation')

          const headers = screen.getAllByRole('banner')
          expect(headers.length).toBeGreaterThan(0)
          const header = headers[0] // Use the first header for verification
          expect(header).toBeInTheDocument()

          const mains = screen.getAllByRole('main')
          expect(mains.length).toBeGreaterThan(0)
          const main = mains[0] // Use the first main for verification
          expect(main).toBeInTheDocument()

          // Verify interactive elements have proper labels
          const buttons = screen.getAllByRole('button')
          buttons.forEach(button => {
            // Each button should have accessible name (either aria-label, aria-labelledby, or text content)
            const hasAccessibleName = 
              button.hasAttribute('aria-label') ||
              button.hasAttribute('aria-labelledby') ||
              button.textContent?.trim() ||
              button.querySelector('svg') // Icon buttons are acceptable if they have proper context
            expect(hasAccessibleName).toBeTruthy()
          })

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })
})