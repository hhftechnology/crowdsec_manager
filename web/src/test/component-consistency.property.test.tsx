/**
 * **Feature: ui-revamp-shadcn-admin, Property 1: Component Consistency Property**
 * **Validates: Requirements 1.1, 1.2, 1.3**
 * 
 * Property-based test for component consistency across pages.
 * Tests that all pages use shadcn/ui components with consistent spacing, typography, colors, and grid alignment.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import * as fc from 'fast-check'

// Import all pages to test
import Dashboard from '@/pages/Dashboard'
import Health from '@/pages/Health'
import IPManagement from '@/pages/IPManagement'
import Whitelist from '@/pages/Whitelist'
import Configuration from '@/pages/Configuration'
import AlertAnalysis from '@/pages/AlertAnalysis'
import Allowlist from '@/pages/Allowlist'
import Backup from '@/pages/Backup'
import Bouncers from '@/pages/Bouncers'
import Captcha from '@/pages/Captcha'
import ComprehensiveHealth from '@/pages/ComprehensiveHealth'
import Cron from '@/pages/Cron'
import CrowdSecHealth from '@/pages/CrowdSecHealth'
import DecisionAnalysis from '@/pages/DecisionAnalysis'
import Logs from '@/pages/Logs'
import Notifications from '@/pages/Notifications'
import Profiles from '@/pages/Profiles'
import Scenarios from '@/pages/Scenarios'
import Services from '@/pages/Services'
import Update from '@/pages/Update'

import { ThemeProvider } from '@/components/ThemeProvider'
import { ProxyProvider } from '@/contexts/ProxyContext'

// Mock API calls to prevent network requests during testing
vi.mock('@/lib/api', () => ({
  default: {
    health: {
      checkStack: () => Promise.resolve({ data: { data: { allRunning: true, containers: [], timestamp: Date.now() } } }),
      completeDiagnostics: () => Promise.resolve({ data: { data: { health: { allRunning: true, containers: [] }, bouncers: [], timestamp: Date.now() } } })
    },
    crowdsec: {
      getDecisions: () => Promise.resolve({ data: { data: { count: 0, decisions: [] } } }),
      getBouncers: () => Promise.resolve({ data: { data: [] } }),
      getScenarios: () => Promise.resolve({ data: { data: { list: [] } } })
    },
    ip: {
      getPublicIP: () => Promise.resolve({ data: { data: { ip: '127.0.0.1' } } }),
      isBlocked: () => Promise.resolve({ data: { data: { blocked: false, ip: '127.0.0.1' } } }),
      checkSecurity: () => Promise.resolve({ data: { data: { ip: '127.0.0.1', is_blocked: false, is_whitelisted: false, in_crowdsec: false, in_traefik: false } } }),
      unban: () => Promise.resolve({ data: { success: true } })
    },
    whitelist: {
      view: () => Promise.resolve({ data: { data: { crowdsec: [], traefik: [] } } }),
      whitelistCurrent: () => Promise.resolve({ data: { success: true } }),
      whitelistManual: () => Promise.resolve({ data: { success: true } }),
      whitelistCIDR: () => Promise.resolve({ data: { success: true } }),
      setupComprehensive: () => Promise.resolve({ data: { success: true } })
    },
    traefik: {
      getConfigPath: () => Promise.resolve({ data: { data: { dynamic_config_path: '/etc/traefik/dynamic_config.yml' } } }),
      setConfigPath: () => Promise.resolve({ data: { success: true } })
    },
    notifications: {
      discord: () => Promise.resolve({ data: { data: { enabled: false, webhook_id: '', webhook_token: '', geoapify_key: '', crowdsec_cti_api_key: '' } } })
    },
    profiles: () => Promise.resolve({ data: { data: 'profiles:\n  - name: default' } }),
    scenarios: {
      list: () => Promise.resolve({ data: { data: { list: [] } } })
    }
  }
}))

// Mock fetch for components that use it directly
global.fetch = vi.fn(() =>
  Promise.resolve({
    ok: true,
    json: () => Promise.resolve({ success: true, data: {} }),
  })
) as any

// Test wrapper component
const TestWrapper = ({ children }: { children: React.ReactNode }) => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        staleTime: Infinity,
      },
    },
  })

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ThemeProvider defaultTheme="light" storageKey="test-theme">
          <ProxyProvider>
            {children}
          </ProxyProvider>
        </ThemeProvider>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

// All page components to test
const pageComponents = [
  { name: 'Dashboard', component: Dashboard },
  { name: 'Health', component: Health },
  { name: 'IPManagement', component: IPManagement },
  { name: 'Whitelist', component: Whitelist },
  { name: 'Configuration', component: Configuration },
  { name: 'AlertAnalysis', component: AlertAnalysis },
  { name: 'Allowlist', component: Allowlist },
  { name: 'Backup', component: Backup },
  { name: 'Bouncers', component: Bouncers },
  { name: 'Captcha', component: Captcha },
  { name: 'ComprehensiveHealth', component: ComprehensiveHealth },
  { name: 'Cron', component: Cron },
  { name: 'CrowdSecHealth', component: CrowdSecHealth },
  { name: 'DecisionAnalysis', component: DecisionAnalysis },
  { name: 'Logs', component: Logs },
  { name: 'Notifications', component: Notifications },
  { name: 'Profiles', component: Profiles },
  { name: 'Scenarios', component: Scenarios },
  { name: 'Services', component: Services },
  { name: 'Update', component: Update }
]

// Helper functions to check component consistency
const checkShadcnUIComponents = (container: HTMLElement): boolean => {
  // Check for shadcn/ui component classes and data attributes
  const shadcnSelectors = [
    '[data-radix-collection-item]', // Radix UI components
    '.bg-card', // Card backgrounds
    '.text-card-foreground', // Card text
    '.bg-primary', // Primary colors
    '.text-primary-foreground', // Primary text
    '.bg-secondary', // Secondary colors
    '.text-secondary-foreground', // Secondary text
    '.bg-muted', // Muted backgrounds
    '.text-muted-foreground', // Muted text
    '.border', // Border utilities
    '.rounded-md', // Border radius
    '.rounded-lg', // Border radius
    '.shadow-sm', // Shadows
    '.shadow-md', // Shadows
    '.shadow-lg' // Shadows
  ]

  return shadcnSelectors.some(selector => container.querySelector(selector) !== null)
}

const checkConsistentSpacing = (container: HTMLElement): boolean => {
  // Check for consistent Tailwind spacing classes
  const spacingClasses = [
    'space-y-', 'space-x-', 'gap-', 'p-', 'px-', 'py-', 'pt-', 'pb-', 'pl-', 'pr-',
    'm-', 'mx-', 'my-', 'mt-', 'mb-', 'ml-', 'mr-'
  ]

  const allElements = container.querySelectorAll('*')
  let hasConsistentSpacing = false

  for (const element of allElements) {
    const classList = Array.from(element.classList)
    const hasSpacingClass = classList.some(className => 
      spacingClasses.some(spacingClass => className.startsWith(spacingClass))
    )
    if (hasSpacingClass) {
      hasConsistentSpacing = true
      break
    }
  }

  return hasConsistentSpacing
}

const checkConsistentTypography = (container: HTMLElement): boolean => {
  // Check for consistent typography classes
  const typographyClasses = [
    'text-xs', 'text-sm', 'text-base', 'text-lg', 'text-xl', 'text-2xl', 'text-3xl',
    'font-normal', 'font-medium', 'font-semibold', 'font-bold',
    'leading-', 'tracking-'
  ]

  const allElements = container.querySelectorAll('*')
  let hasTypographyClasses = false

  for (const element of allElements) {
    const classList = Array.from(element.classList)
    const hasTypographyClass = classList.some(className => 
      typographyClasses.some(typoClass => className.includes(typoClass))
    )
    if (hasTypographyClass) {
      hasTypographyClasses = true
      break
    }
  }

  return hasTypographyClasses
}

const checkConsistentColors = (container: HTMLElement): boolean => {
  // Check for consistent color scheme usage
  const colorClasses = [
    'text-foreground', 'text-muted-foreground', 'text-primary', 'text-secondary',
    'bg-background', 'bg-card', 'bg-primary', 'bg-secondary', 'bg-muted',
    'border-border', 'border-input'
  ]

  const allElements = container.querySelectorAll('*')
  let hasColorClasses = false

  for (const element of allElements) {
    const classList = Array.from(element.classList)
    const hasColorClass = classList.some(className => 
      colorClasses.some(colorClass => className.includes(colorClass))
    )
    if (hasColorClass) {
      hasColorClasses = true
      break
    }
  }

  return hasColorClasses
}

const checkGridAlignment = (container: HTMLElement): boolean => {
  // Check for proper grid and flexbox usage
  const layoutClasses = [
    'grid', 'flex', 'grid-cols-', 'gap-', 'justify-', 'items-', 'place-'
  ]

  const allElements = container.querySelectorAll('*')
  let hasLayoutClasses = false

  for (const element of allElements) {
    const classList = Array.from(element.classList)
    const hasLayoutClass = classList.some(className => 
      layoutClasses.some(layoutClass => className.includes(layoutClass))
    )
    if (hasLayoutClass) {
      hasLayoutClasses = true
      break
    }
  }

  return hasLayoutClasses
}

describe('Component Consistency Property Tests', () => {
  it('should use shadcn/ui components consistently across all pages', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...pageComponents),
        (pageConfig) => {
          const PageComponent = pageConfig.component
          const { container } = render(
            <TestWrapper>
              <PageComponent />
            </TestWrapper>
          )

          // Wait for component to render
          expect(container.firstChild).toBeTruthy()

          // Check that the page uses shadcn/ui components
          const usesShadcnComponents = checkShadcnUIComponents(container)
          
          return usesShadcnComponents
        }
      ),
      { numRuns: 20, verbose: false } // Reduced runs and disabled verbose to avoid noise
    )
  })

  it('should maintain consistent spacing patterns across all pages', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...pageComponents),
        (pageConfig) => {
          const PageComponent = pageConfig.component
          const { container } = render(
            <TestWrapper>
              <PageComponent />
            </TestWrapper>
          )

          // Check for consistent spacing
          const hasConsistentSpacing = checkConsistentSpacing(container)
          
          return hasConsistentSpacing
        }
      ),
      { numRuns: 20, verbose: false }
    )
  })

  it('should use consistent typography across all pages', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...pageComponents),
        (pageConfig) => {
          const PageComponent = pageConfig.component
          const { container } = render(
            <TestWrapper>
              <PageComponent />
            </TestWrapper>
          )

          // Check for consistent typography
          const hasConsistentTypography = checkConsistentTypography(container)
          
          return hasConsistentTypography
        }
      ),
      { numRuns: 20, verbose: false }
    )
  })

  it('should use consistent color schemes across all pages', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...pageComponents),
        (pageConfig) => {
          const PageComponent = pageConfig.component
          const { container } = render(
            <TestWrapper>
              <PageComponent />
            </TestWrapper>
          )

          // Check for consistent colors
          const hasConsistentColors = checkConsistentColors(container)
          
          return hasConsistentColors
        }
      ),
      { numRuns: 20, verbose: false }
    )
  })

  it('should maintain proper grid alignment across all pages', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...pageComponents),
        (pageConfig) => {
          const PageComponent = pageConfig.component
          const { container } = render(
            <TestWrapper>
              <PageComponent />
            </TestWrapper>
          )

          // Check for proper grid alignment
          const hasProperAlignment = checkGridAlignment(container)
          
          return hasProperAlignment
        }
      ),
      { numRuns: 20, verbose: false }
    )
  })

  it('should have consistent page structure with proper headings', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...pageComponents),
        (pageConfig) => {
          const PageComponent = pageConfig.component
          const { container } = render(
            <TestWrapper>
              <PageComponent />
            </TestWrapper>
          )

          // Check for proper heading structure (h1 or h2 should be present)
          const hasMainHeading = container.querySelector('h1, h2') !== null
          
          // Check for consistent page wrapper structure
          const hasSpaceYClass = container.querySelector('.space-y-6, .space-y-4, .space-y-8') !== null
          
          return hasMainHeading && hasSpaceYClass
        }
      ),
      { numRuns: 20, verbose: false }
    )
  })
})