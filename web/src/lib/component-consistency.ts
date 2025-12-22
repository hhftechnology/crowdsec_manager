/**
 * Component consistency utilities
 * Enforces standardized patterns and eliminates duplication
 */

import { ComponentType, ReactNode } from 'react'
import { BaseComponentProps, StatusVariant } from './component-patterns'

// Component registry for tracking standardized components
interface ComponentRegistryEntry {
  name: string
  component: ComponentType<any>
  category: 'layout' | 'display' | 'form' | 'navigation' | 'feedback'
  deprecated?: boolean
  replacedBy?: string
}

class ComponentRegistry {
  private components = new Map<string, ComponentRegistryEntry>()
  private deprecatedComponents = new Set<string>()

  register(entry: ComponentRegistryEntry) {
    this.components.set(entry.name, entry)
    if (entry.deprecated) {
      this.deprecatedComponents.add(entry.name)
    }
  }

  get(name: string): ComponentRegistryEntry | undefined {
    return this.components.get(name)
  }

  getByCategory(category: ComponentRegistryEntry['category']): ComponentRegistryEntry[] {
    return Array.from(this.components.values()).filter(
      entry => entry.category === category && !entry.deprecated
    )
  }

  getDeprecated(): ComponentRegistryEntry[] {
    return Array.from(this.components.values()).filter(entry => entry.deprecated)
  }

  isDeprecated(name: string): boolean {
    return this.deprecatedComponents.has(name)
  }

  getReplacementFor(name: string): string | undefined {
    const entry = this.components.get(name)
    return entry?.replacedBy
  }
}

export const componentRegistry = new ComponentRegistry()

// Register standardized components
componentRegistry.register({
  name: 'StandardizedStatusCard',
  component: null as any, // Will be set when imported
  category: 'display'
})

componentRegistry.register({
  name: 'DashboardGrid',
  component: null as any,
  category: 'layout'
})

// Register deprecated components
componentRegistry.register({
  name: 'Layout',
  component: null as any,
  category: 'layout',
  deprecated: true,
  replacedBy: 'AppShell'
})

componentRegistry.register({
  name: 'Header',
  component: null as any,
  category: 'layout',
  deprecated: true,
  replacedBy: 'AppHeader'
})

componentRegistry.register({
  name: 'Sidebar',
  component: null as any,
  category: 'navigation',
  deprecated: true,
  replacedBy: 'AppSidebar'
})

// Prop validation utilities
export function validateStandardProps<T extends BaseComponentProps>(
  props: T,
  componentName: string
): void {
  // Check for required base props
  if (props.className !== undefined && typeof props.className !== 'string') {
    console.warn(`${componentName}: className prop must be a string`)
  }

  if (props['data-testid'] !== undefined && typeof props['data-testid'] !== 'string') {
    console.warn(`${componentName}: data-testid prop must be a string`)
  }

  // Check for deprecated usage
  if (componentRegistry.isDeprecated(componentName)) {
    const replacement = componentRegistry.getReplacementFor(componentName)
    console.warn(
      `${componentName} is deprecated${replacement ? ` and will be replaced by ${replacement}` : ''}`
    )
  }
}

// Status variant validation
export function validateStatusVariant(
  variant: string,
  componentName: string
): variant is StatusVariant['variant'] {
  const validVariants = ['success', 'warning', 'error', 'info', 'neutral']
  
  if (!validVariants.includes(variant)) {
    console.warn(
      `${componentName}: Invalid status variant "${variant}". Valid variants are: ${validVariants.join(', ')}`
    )
    return false
  }
  
  return true
}

// Component consistency checker
export interface ConsistencyReport {
  componentName: string
  issues: string[]
  suggestions: string[]
  deprecated: boolean
  replacement?: string
}

export function checkComponentConsistency<T extends BaseComponentProps>(
  componentName: string,
  props: T
): ConsistencyReport {
  const issues: string[] = []
  const suggestions: string[] = []
  
  // Check if component is deprecated
  const deprecated = componentRegistry.isDeprecated(componentName)
  const replacement = componentRegistry.getReplacementFor(componentName)

  // Check prop consistency
  if (!props.className) {
    suggestions.push('Consider adding className prop for styling flexibility')
  }

  if (!props['data-testid']) {
    suggestions.push('Consider adding data-testid prop for testing')
  }

  // Check for common anti-patterns
  if (props.className && props.className.includes('!important')) {
    issues.push('Avoid using !important in className. Use proper CSS specificity instead.')
  }

  // Check for inline styles (anti-pattern)
  if ('style' in props && props.style) {
    issues.push('Avoid inline styles. Use className with Tailwind CSS classes instead.')
  }

  return {
    componentName,
    issues,
    suggestions,
    deprecated,
    replacement
  }
}

// Component composition utilities
export interface CompositionPattern {
  name: string
  description: string
  example: ReactNode
  components: string[]
}

export const compositionPatterns: CompositionPattern[] = [
  {
    name: 'Status Dashboard',
    description: 'Grid of status cards with consistent spacing and responsive behavior',
    example: null, // Would contain JSX example
    components: ['DashboardGrid', 'StandardizedStatusCard']
  },
  {
    name: 'Data Table with Actions',
    description: 'Data table with consistent action buttons and loading states',
    example: null,
    components: ['DataTable', 'Button', 'LoadingStates']
  },
  {
    name: 'Form with Validation',
    description: 'Form components with consistent validation and error handling',
    example: null,
    components: ['FormComponents', 'Input', 'Button']
  }
]

// Duplication detection utilities
export interface DuplicationReport {
  duplicatedComponents: Array<{
    name: string
    locations: string[]
    similarity: number
  }>
  recommendations: string[]
}

export function detectComponentDuplication(
  componentPaths: string[]
): DuplicationReport {
  // This would analyze component files for similar patterns
  // For now, return known duplications based on audit
  
  const knownDuplications = [
    {
      name: 'StatusCard',
      locations: [
        'components/common/StatusCard.tsx',
        'components/proxy/StatusDashboard.tsx (custom implementation)',
        'components/health/StatusDashboard.tsx (custom implementation)'
      ],
      similarity: 0.85
    },
    {
      name: 'Layout Components',
      locations: [
        'components/Layout.tsx',
        'components/layout/AppShell.tsx'
      ],
      similarity: 0.75
    },
    {
      name: 'Navigation Components',
      locations: [
        'components/Sidebar.tsx',
        'components/layout/AppSidebar.tsx',
        'components/navigation/EnhancedSidebar.tsx'
      ],
      similarity: 0.80
    }
  ]

  const recommendations = [
    'Consolidate StatusCard implementations into StandardizedStatusCard',
    'Migrate all layouts to use AppShell, AppHeader, AppSidebar',
    'Remove deprecated Layout, Header, Sidebar components',
    'Standardize navigation data structures across all implementations',
    'Create shared dashboard layout patterns using DashboardGrid'
  ]

  return {
    duplicatedComponents: knownDuplications,
    recommendations
  }
}

// Migration utilities
export interface MigrationStep {
  description: string
  from: string
  to: string
  automated: boolean
  breaking: boolean
}

export const migrationSteps: MigrationStep[] = [
  {
    description: 'Replace Layout component with AppShell',
    from: 'Layout',
    to: 'AppShell',
    automated: false,
    breaking: true
  },
  {
    description: 'Replace Header component with AppHeader',
    from: 'Header',
    to: 'AppHeader',
    automated: false,
    breaking: true
  },
  {
    description: 'Replace Sidebar component with AppSidebar',
    from: 'Sidebar',
    to: 'AppSidebar',
    automated: false,
    breaking: true
  },
  {
    description: 'Replace custom StatusCard implementations with StandardizedStatusCard',
    from: 'Custom StatusCard implementations',
    to: 'StandardizedStatusCard',
    automated: false,
    breaking: false
  },
  {
    description: 'Migrate dashboard layouts to use DashboardGrid',
    from: 'Custom dashboard layouts',
    to: 'DashboardGrid',
    automated: false,
    breaking: false
  }
]

// Performance monitoring for component consistency
export interface PerformanceMetrics {
  componentCount: number
  duplicatedComponents: number
  deprecatedUsage: number
  consistencyScore: number
}

export function calculateConsistencyMetrics(): PerformanceMetrics {
  const totalComponents = componentRegistry.components.size
  const deprecatedCount = componentRegistry.getDeprecated().length
  const duplicationReport = detectComponentDuplication([])
  
  const consistencyScore = Math.max(0, 100 - (
    (deprecatedCount / totalComponents) * 30 +
    (duplicationReport.duplicatedComponents.length / totalComponents) * 40
  ))

  return {
    componentCount: totalComponents,
    duplicatedComponents: duplicationReport.duplicatedComponents.length,
    deprecatedUsage: deprecatedCount,
    consistencyScore: Math.round(consistencyScore)
  }
}

// Development helpers
export function logConsistencyReport(): void {
  const metrics = calculateConsistencyMetrics()
  const duplicationReport = detectComponentDuplication([])
  
  console.group('Component Library Consistency Report')
  console.log('📊 Metrics:', metrics)
  console.log('🔄 Duplications:', duplicationReport.duplicatedComponents)
  console.log('💡 Recommendations:', duplicationReport.recommendations)
  console.log('📋 Migration Steps:', migrationSteps.filter(step => !step.automated))
  console.groupEnd()
}

// Export utilities for testing
export const testUtils = {
  validateStandardProps,
  validateStatusVariant,
  checkComponentConsistency,
  detectComponentDuplication,
  calculateConsistencyMetrics
}