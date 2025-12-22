/**
 * Standardized DashboardGrid component
 * Eliminates duplication in dashboard layouts across different features
 */

import * as React from "react"
import { cn } from "@/lib/utils"
import { BaseComponentProps } from "@/lib/component-patterns"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Button } from "@/components/ui/button"
import { RefreshCw, AlertTriangle, Clock } from "lucide-react"

// Grid layout configurations
export type GridLayout = 
  | '1-col' 
  | '2-col' 
  | '3-col' 
  | '4-col' 
  | '2-1-1' // 2 cols on top, 1 col below
  | '1-2-1' // 1 col, 2 cols, 1 col
  | 'auto'  // Auto-fit based on content

export interface DashboardSection {
  id: string
  title?: string
  description?: string
  content: React.ReactNode
  span?: number // Grid span for this section
  loading?: boolean
  error?: string
}

export interface DashboardTab {
  id: string
  label: string
  sections: DashboardSection[]
  layout?: GridLayout
}

export interface DashboardGridProps extends BaseComponentProps {
  title?: string
  description?: string
  layout?: GridLayout
  sections?: DashboardSection[]
  tabs?: DashboardTab[]
  loading?: boolean
  error?: string
  lastUpdated?: Date
  onRefresh?: () => void
  actions?: React.ReactNode
  alert?: {
    variant: 'default' | 'destructive'
    title: string
    description: string
  }
}

const gridLayoutClasses: Record<GridLayout, string> = {
  '1-col': 'grid-cols-1',
  '2-col': 'grid-cols-1 md:grid-cols-2',
  '3-col': 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3',
  '4-col': 'grid-cols-1 md:grid-cols-2 lg:grid-cols-4',
  '2-1-1': 'grid-cols-1 md:grid-cols-2 lg:grid-cols-4',
  '1-2-1': 'grid-cols-1 md:grid-cols-2 lg:grid-cols-4',
  'auto': 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4'
}

function DashboardSectionComponent({ 
  section, 
  loading 
}: { 
  section: DashboardSection
  loading?: boolean 
}) {
  if (loading || section.loading) {
    return (
      <Card className="animate-pulse">
        <CardHeader>
          <div className="h-5 w-32 bg-muted rounded" />
          <div className="h-3 w-48 bg-muted rounded" />
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="h-16 bg-muted rounded" />
            <div className="h-4 bg-muted rounded" />
          </div>
        </CardContent>
      </Card>
    )
  }

  if (section.error) {
    return (
      <Card className="border-red-200 bg-red-50/50 dark:border-red-800 dark:bg-red-950/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-red-600 dark:text-red-400">
            <AlertTriangle className="h-4 w-4" />
            {section.title || 'Error'}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-red-600 dark:text-red-400">
            {section.error}
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className={cn(
      section.span && section.span > 1 && `md:col-span-${section.span}`
    )}>
      {section.title || section.description ? (
        <Card>
          <CardHeader>
            {section.title && <CardTitle>{section.title}</CardTitle>}
            {section.description && (
              <CardDescription>{section.description}</CardDescription>
            )}
          </CardHeader>
          <CardContent>
            {section.content}
          </CardContent>
        </Card>
      ) : (
        section.content
      )}
    </div>
  )
}

function DashboardSections({ 
  sections, 
  layout = 'auto', 
  loading 
}: { 
  sections: DashboardSection[]
  layout?: GridLayout
  loading?: boolean 
}) {
  return (
    <div className={cn(
      "grid gap-4",
      gridLayoutClasses[layout]
    )}>
      {sections.map((section) => (
        <DashboardSectionComponent
          key={section.id}
          section={section}
          loading={loading}
        />
      ))}
    </div>
  )
}

/**
 * Standardized DashboardGrid component
 * Provides consistent dashboard layouts across all features
 */
export function DashboardGrid({
  title,
  description,
  layout = 'auto',
  sections = [],
  tabs,
  loading = false,
  error,
  lastUpdated,
  onRefresh,
  actions,
  alert,
  className,
  'data-testid': testId,
  children,
  ...props
}: DashboardGridProps) {
  return (
    <div 
      className={cn("space-y-6", className)}
      data-testid={testId}
      {...props}
    >
      {/* Dashboard Header */}
      {(title || description || actions || onRefresh) && (
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            {title && (
              <h2 className="text-2xl font-bold tracking-tight">{title}</h2>
            )}
            {description && (
              <p className="text-muted-foreground">{description}</p>
            )}
          </div>
          
          <div className="flex items-center gap-2">
            {lastUpdated && (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Clock className="h-4 w-4" />
                <span>
                  Last updated: {lastUpdated.toLocaleTimeString()}
                </span>
              </div>
            )}
            
            {onRefresh && (
              <Button
                variant="outline"
                size="sm"
                onClick={onRefresh}
                disabled={loading}
              >
                <RefreshCw className={cn(
                  "h-4 w-4 mr-2",
                  loading && "animate-spin"
                )} />
                Refresh
              </Button>
            )}
            
            {actions}
          </div>
        </div>
      )}

      {/* Error State */}
      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* System Alert */}
      {alert && (
        <Alert variant={alert.variant}>
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>{alert.title}</AlertTitle>
          <AlertDescription>{alert.description}</AlertDescription>
        </Alert>
      )}

      {/* Dashboard Content */}
      {tabs ? (
        <Tabs defaultValue={tabs[0]?.id} className="space-y-4">
          <TabsList className="grid w-full" style={{ gridTemplateColumns: `repeat(${tabs.length}, 1fr)` }}>
            {tabs.map((tab) => (
              <TabsTrigger key={tab.id} value={tab.id}>
                {tab.label}
              </TabsTrigger>
            ))}
          </TabsList>
          
          {tabs.map((tab) => (
            <TabsContent key={tab.id} value={tab.id} className="space-y-4">
              <DashboardSections
                sections={tab.sections}
                layout={tab.layout || layout}
                loading={loading}
              />
            </TabsContent>
          ))}
        </Tabs>
      ) : sections.length > 0 ? (
        <DashboardSections
          sections={sections}
          layout={layout}
          loading={loading}
        />
      ) : (
        children
      )}
    </div>
  )
}

// Preset dashboard configurations for common use cases
export interface SystemDashboardProps extends Omit<DashboardGridProps, 'tabs'> {
  systemHealth?: React.ReactNode
  containerStatus?: React.ReactNode
  securityMetrics?: React.ReactNode
  quickActions?: React.ReactNode
}

export function SystemDashboard({
  systemHealth,
  containerStatus,
  securityMetrics,
  quickActions,
  ...props
}: SystemDashboardProps) {
  const tabs: DashboardTab[] = [
    {
      id: 'overview',
      label: 'Overview',
      layout: '2-col',
      sections: [
        ...(systemHealth ? [{ id: 'health', content: systemHealth }] : []),
        ...(quickActions ? [{ id: 'actions', content: quickActions }] : []),
      ]
    },
    {
      id: 'containers',
      label: 'Containers',
      layout: '1-col',
      sections: [
        ...(containerStatus ? [{ id: 'containers', content: containerStatus }] : []),
      ]
    },
    {
      id: 'security',
      label: 'Security',
      layout: '2-col',
      sections: [
        ...(securityMetrics ? [{ id: 'security', content: securityMetrics }] : []),
      ]
    }
  ]

  return (
    <DashboardGrid
      tabs={tabs}
      {...props}
    />
  )
}

export interface MetricsDashboardProps extends Omit<DashboardGridProps, 'sections'> {
  metrics: Array<{
    id: string
    title: string
    content: React.ReactNode
    span?: number
  }>
}

export function MetricsDashboard({
  metrics,
  layout = '4-col',
  ...props
}: MetricsDashboardProps) {
  const sections: DashboardSection[] = metrics.map(metric => ({
    id: metric.id,
    title: metric.title,
    content: metric.content,
    span: metric.span
  }))

  return (
    <DashboardGrid
      sections={sections}
      layout={layout}
      {...props}
    />
  )
}

export default DashboardGrid