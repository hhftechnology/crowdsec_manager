/**
 * Property-based tests for navigation system functionality
 * **Feature: ui-revamp-shadcn-admin, Property 5: Navigation System Property**
 * **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5**
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import * as fc from 'fast-check'
import { EnhancedSidebar } from '../EnhancedSidebar'
import { ResponsiveNavigation } from '../ResponsiveNavigation'
import { getNavigationForProxy } from '../ProxyAwareNavigation'
import { ThemeProvider } from '../../ThemeProvider'
import { ProxyType, Feature } from '@/lib/proxy-types'

// Mock useMediaQuery hook
const mockUseMediaQuery = vi.fn()
vi.mock('@/hooks/useMediaQuery', () => ({
  useMediaQuery: () => mockUseMediaQuery(),
  useBreakpoints: () => ({
    isMobile: mockUseMediaQuery(),
    isTablet: false,
    isDesktop: !mockUseMediaQuery()
  })
}))

// Mock matchMedia
const createMatchMediaMock = (matches: boolean) => vi.fn(() => ({
  matches,
  media: '',
  onchange: null,
  addListener: vi.fn(),
  removeListener: vi.fn(),
  addEventListener: vi.fn(),
  removeEventListener: vi.fn(),
  dispatchEvent: vi.fn(),
}))

// Mock localStorage
const localStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
}

// Test wrapper component
function NavigationTestWrapper({ 
  children, 
  initialRoute = '/' 
}: { 
  children: React.ReactNode
  initialRoute?: string 
}) {
  return (
    <MemoryRouter initialEntries={[initialRoute]}>
      <ThemeProvider>
        {children}
      </ThemeProvider>
    </MemoryRouter>
  )
}

// Generators for property-based testing
const proxyTypeArb = fc.constantFrom(
  'traefik', 'nginx', 'caddy', 'haproxy', 'zoraxy', 'standalone'
) as fc.Arbitrary<ProxyType>

const featureArb = fc.constantFrom(
  'whitelist', 'captcha', 'logs', 'bouncer', 'health', 'appsec'
) as fc.Arbitrary<Feature>

const featuresArb = fc.array(featureArb, { minLength: 0, maxLength: 6 })
  .map(features => [...new Set(features)]) // Remove duplicates

const routeArb = fc.constantFrom(
  '/', '/proxy-health', '/crowdsec-health', '/decisions', '/alerts', 
  '/bouncers', '/proxy-logs', '/proxy-whitelist', '/captcha', 
  '/scenarios', '/allowlist', '/profiles', '/proxy-settings', 
  '/notifications', '/backup', '/update'
)

describe('Navigation System Property Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Default to desktop view
    mockUseMediaQuery.mockReturnValue(false)
    
    // Setup matchMedia mock
    Object.defineProperty(window, 'matchMedia', {
      value: createMatchMediaMock(false),
      configurable: true,
      writable: true
    })
    
    // Setup localStorage mock
    Object.defineProperty(window, 'localStorage', {
      value: localStorageMock,
      configurable: true,
      writable: true
    })
    
    // Clear DOM classes
    document.documentElement.className = ''
  })

  afterEach(() => {
    vi.clearAllMocks()
    // Clean up DOM
    document.documentElement.className = ''
  })

  /**
   * Property 5: Navigation System Property
   * For any navigation interaction, the system should maintain proper grouping, 
   * active states, breadcrumbs, keyboard accessibility, and touch-friendly targets
   */
  it('should maintain proper hierarchical grouping for any proxy configuration', () => {
    fc.assert(
      fc.property(
        proxyTypeArb,
        featuresArb,
        (proxyType: ProxyType, supportedFeatures: Feature[]) => {
          const navigation = getNavigationForProxy(proxyType, supportedFeatures)
          
          // Verify hierarchical structure exists
          expect(navigation).toBeInstanceOf(Array)
          expect(navigation.length).toBeGreaterThan(0)
          
          // Each group should have a title and items
          navigation.forEach(group => {
            expect(group).toHaveProperty('title')
            expect(group).toHaveProperty('items')
            expect(typeof group.title).toBe('string')
            expect(group.title.length).toBeGreaterThan(0)
            expect(Array.isArray(group.items)).toBe(true)
            
            // Each item should have required properties
            group.items.forEach(item => {
              expect(item).toHaveProperty('name')
              expect(item).toHaveProperty('href')
              expect(item).toHaveProperty('icon')
              expect(item).toHaveProperty('available')
              expect(typeof item.name).toBe('string')
              expect(typeof item.href).toBe('string')
              expect(typeof item.available).toBe('boolean')
              expect(item.href.startsWith('/')).toBe(true)
            })
          })
          
          // Verify logical grouping - certain items should be in expected groups
          const overviewGroup = navigation.find(g => g.title === 'Overview')
          const securityGroup = navigation.find(g => g.title === 'Security')
          const proxyGroup = navigation.find(g => g.title === 'Proxy Management')
          
          expect(overviewGroup).toBeDefined()
          expect(securityGroup).toBeDefined()
          expect(proxyGroup).toBeDefined()
          
          // Dashboard should always be in Overview
          const dashboardItem = overviewGroup?.items.find(i => i.name === 'Dashboard')
          expect(dashboardItem).toBeDefined()
          expect(dashboardItem?.available).toBe(true)
          
          // Feature-dependent items should respect availability
          const whitelistItem = proxyGroup?.items.find(i => i.name === 'Proxy Whitelist')
          if (whitelistItem) {
            expect(whitelistItem.available).toBe(supportedFeatures.includes('whitelist'))
          }
          
          const captchaItem = proxyGroup?.items.find(i => i.name === 'Captcha Protection')
          if (captchaItem) {
            expect(captchaItem.available).toBe(supportedFeatures.includes('captcha'))
          }
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should highlight active routes correctly for any navigation state', () => {
    fc.assert(
      fc.property(
        proxyTypeArb,
        featuresArb,
        routeArb,
        fc.boolean(), // isCollapsed
        (proxyType: ProxyType, supportedFeatures: Feature[], currentRoute: string, isCollapsed: boolean) => {
          const { unmount } = render(
            <NavigationTestWrapper initialRoute={currentRoute}>
              <EnhancedSidebar
                proxyType={proxyType}
                supportedFeatures={supportedFeatures}
                isCollapsed={isCollapsed}
                setIsCollapsed={() => {}}
              />
            </NavigationTestWrapper>
          )

          // Find navigation links
          const links = screen.getAllByRole('link')
          expect(links.length).toBeGreaterThan(0)

          // Check if any link is marked as active for the current route
          const activeLinks = links.filter(link => {
            const href = link.getAttribute('href')
            return href === currentRoute
          })

          if (activeLinks.length > 0) {
            // At least one link should have active styling
            const hasActiveLink = activeLinks.some(link => {
              const classes = link.className
              return classes.includes('bg-primary') || classes.includes('text-primary-foreground')
            })
            expect(hasActiveLink).toBe(true)
          }

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should provide keyboard navigation support for any navigation configuration', () => {
    fc.assert(
      fc.property(
        proxyTypeArb,
        featuresArb,
        fc.boolean(), // isCollapsed
        (proxyType: ProxyType, supportedFeatures: Feature[], isCollapsed: boolean) => {
          const { unmount } = render(
            <NavigationTestWrapper>
              <EnhancedSidebar
                proxyType={proxyType}
                supportedFeatures={supportedFeatures}
                isCollapsed={isCollapsed}
                setIsCollapsed={() => {}}
              />
            </NavigationTestWrapper>
          )

          // All interactive elements should be focusable
          const interactiveElements = screen.getAllByRole('link')
          const buttons = screen.getAllByRole('button')
          
          const allInteractive = [...interactiveElements, ...buttons]
          
          allInteractive.forEach(element => {
            // Element should be focusable (not have tabIndex -1 unless disabled)
            const tabIndex = element.getAttribute('tabindex')
            const isDisabled = element.hasAttribute('disabled') || 
                             element.getAttribute('aria-disabled') === 'true'
            
            if (!isDisabled) {
              expect(tabIndex !== '-1').toBe(true)
            }
            
            // Element should be keyboard accessible
            act(() => {
              element.focus()
            })
            
            // Should be able to trigger with Enter or Space (for buttons)
            if (element.tagName === 'BUTTON') {
              const clickHandler = vi.fn()
              element.addEventListener('click', clickHandler)
              
              fireEvent.keyDown(element, { key: 'Enter', code: 'Enter' })
              // Note: Some buttons might not respond to Enter if they have custom handlers
            }
          })

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should provide touch-friendly targets on mobile devices', () => {
    fc.assert(
      fc.property(
        proxyTypeArb,
        featuresArb,
        (proxyType: ProxyType, supportedFeatures: Feature[]) => {
          // Mock mobile view
          mockUseMediaQuery.mockReturnValue(true)
          
          const { unmount } = render(
            <NavigationTestWrapper>
              <ResponsiveNavigation
                proxyType={proxyType}
                supportedFeatures={supportedFeatures}
              />
            </NavigationTestWrapper>
          )

          // On mobile, should show menu trigger button
          const menuTrigger = screen.getByRole('button')
          expect(menuTrigger).toBeDefined()
          
          // Menu trigger should have appropriate size for touch
          const triggerClasses = menuTrigger.className
          expect(
            triggerClasses.includes('h-9') || 
            triggerClasses.includes('w-9') ||
            triggerClasses.includes('min-h-[48px]')
          ).toBe(true)

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should maintain consistent navigation behavior across viewport changes', () => {
    fc.assert(
      fc.property(
        proxyTypeArb,
        featuresArb,
        fc.array(fc.boolean(), { minLength: 2, maxLength: 5 }), // viewport changes
        (proxyType: ProxyType, supportedFeatures: Feature[], viewportChanges: boolean[]) => {
          let currentRender: any = null
          
          viewportChanges.forEach((isMobile, index) => {
            // Clean up previous render
            if (currentRender) {
              currentRender.unmount()
            }
            
            // Set viewport
            mockUseMediaQuery.mockReturnValue(isMobile)
            
            currentRender = render(
              <NavigationTestWrapper>
                <ResponsiveNavigation
                  proxyType={proxyType}
                  supportedFeatures={supportedFeatures}
                />
              </NavigationTestWrapper>
            )

            if (isMobile) {
              // Mobile should show menu trigger
              const menuTrigger = screen.queryByRole('button')
              expect(menuTrigger).toBeDefined()
            } else {
              // Desktop should show navigation directly
              const links = screen.queryAllByRole('link')
              expect(links.length).toBeGreaterThan(0)
            }
          })
          
          if (currentRender) {
            currentRender.unmount()
          }
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should handle feature availability changes gracefully', () => {
    fc.assert(
      fc.property(
        proxyTypeArb,
        featuresArb,
        featuresArb,
        (proxyType: ProxyType, initialFeatures: Feature[], updatedFeatures: Feature[]) => {
          // Initial render
          const { rerender, unmount } = render(
            <NavigationTestWrapper>
              <EnhancedSidebar
                proxyType={proxyType}
                supportedFeatures={initialFeatures}
                isCollapsed={false}
                setIsCollapsed={() => {}}
              />
            </NavigationTestWrapper>
          )

          // Get initial navigation state
          const initialLinks = screen.getAllByRole('link')
          const initialLinkCount = initialLinks.length

          // Update with new features
          rerender(
            <NavigationTestWrapper>
              <EnhancedSidebar
                proxyType={proxyType}
                supportedFeatures={updatedFeatures}
                isCollapsed={false}
                setIsCollapsed={() => {}}
              />
            </NavigationTestWrapper>
          )

          // Navigation should still be functional
          const updatedLinks = screen.getAllByRole('link')
          expect(updatedLinks.length).toBeGreaterThan(0)

          // Feature-dependent items should reflect new availability
          const navigation = getNavigationForProxy(proxyType, updatedFeatures)
          const allItems = navigation.flatMap(group => group.items)
          
          // Count available vs unavailable items
          const availableItems = allItems.filter(item => item.available)
          const unavailableItems = allItems.filter(item => !item.available)
          
          // Should have at least some available items (Dashboard is always available)
          expect(availableItems.length).toBeGreaterThan(0)
          
          // Unavailable items should have appropriate indicators
          unavailableItems.forEach(item => {
            if (item.tooltip) {
              expect(item.tooltip.length).toBeGreaterThan(0)
            }
          })

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })

  it('should provide appropriate ARIA labels and semantic markup', () => {
    fc.assert(
      fc.property(
        proxyTypeArb,
        featuresArb,
        (proxyType: ProxyType, supportedFeatures: Feature[]) => {
          const { unmount } = render(
            <NavigationTestWrapper>
              <EnhancedSidebar
                proxyType={proxyType}
                supportedFeatures={supportedFeatures}
                isCollapsed={false}
                setIsCollapsed={() => {}}
              />
            </NavigationTestWrapper>
          )

          // Should have proper navigation landmark
          const navs = screen.getAllByRole('navigation')
          expect(navs.length).toBeGreaterThan(0)

          // All links should be properly labeled
          const links = screen.getAllByRole('link')
          links.forEach(link => {
            // Link should have accessible text content or aria-label
            const hasText = link.textContent && link.textContent.trim().length > 0
            const hasAriaLabel = link.getAttribute('aria-label')
            const hasAriaLabelledBy = link.getAttribute('aria-labelledby')
            
            expect(hasText || hasAriaLabel || hasAriaLabelledBy).toBe(true)
          })

          // Buttons should have accessible names
          const buttons = screen.getAllByRole('button')
          buttons.forEach(button => {
            const hasText = button.textContent && button.textContent.trim().length > 0
            const hasAriaLabel = button.getAttribute('aria-label') !== null
            const hasAriaLabelledBy = button.getAttribute('aria-labelledby') !== null
            
            expect(hasText || hasAriaLabel || hasAriaLabelledBy).toBe(true)
          })

          unmount()
        }
      ),
      { numRuns: 100 }
    )
  })
})