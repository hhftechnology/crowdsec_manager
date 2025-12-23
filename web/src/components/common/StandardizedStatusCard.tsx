/**
 * Standardized StatusCard component that eliminates duplication
 * Consolidates functionality from multiple StatusCard implementations
 */

import { TrendingUp, TrendingDown, Minus, CheckCircle2, XCircle, AlertTriangle, Info } from "lucide-react"
import { cn } from "@/lib/utils"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { 
  StatusCardBaseProps, 
  TrendData, 
  BaseComponentProps,
  StatusVariant 
} from "@/lib/component-patterns"

// Extended props for the standardized status card
export interface StandardizedStatusCardProps extends StatusCardBaseProps {
  trend?: TrendData
  badge?: {
    text: string
    variant?: 'default' | 'secondary' | 'destructive' | 'outline'
  }
  compact?: boolean
  interactive?: boolean
}

// Status styling configuration
const statusStyles = {
  success: {
    card: "border-green-200 bg-green-50/50 dark:border-green-800 dark:bg-green-950/50",
    icon: "text-green-600 dark:text-green-400",
    badge: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300",
    statusIcon: CheckCircle2
  },
  warning: {
    card: "border-yellow-200 bg-yellow-50/50 dark:border-yellow-800 dark:bg-yellow-950/50",
    icon: "text-yellow-600 dark:text-yellow-400",
    badge: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300",
    statusIcon: AlertTriangle
  },
  error: {
    card: "border-red-200 bg-red-50/50 dark:border-red-800 dark:bg-red-950/50",
    icon: "text-red-600 dark:text-red-400",
    badge: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300",
    statusIcon: XCircle
  },
  info: {
    card: "border-blue-200 bg-blue-50/50 dark:border-blue-800 dark:bg-blue-950/50",
    icon: "text-blue-600 dark:text-blue-400",
    badge: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300",
    statusIcon: Info
  },
  neutral: {
    card: "",
    icon: "text-muted-foreground",
    badge: "bg-muted text-muted-foreground",
    statusIcon: Info
  }
} as const

const trendIcons = {
  up: TrendingUp,
  down: TrendingDown,
  neutral: Minus
} as const

const trendColors = {
  up: "text-green-600 dark:text-green-400",
  down: "text-red-600 dark:text-red-400",
  neutral: "text-muted-foreground"
} as const

/**
 * Standardized StatusCard component
 * Eliminates duplication by providing a single, comprehensive status card implementation
 */
export function StandardizedStatusCard({
  title,
  value,
  description,
  icon: Icon,
  variant = 'neutral',
  trend,
  badge,
  loading = false,
  compact = false,
  interactive = false,
  className,
  onClick,
  'data-testid': testId,
  ...props
}: StandardizedStatusCardProps) {
  const styles = statusStyles[variant]
  const TrendIcon = trend ? trendIcons[trend.direction] : null
  const trendColor = trend ? trendColors[trend.direction] : ""
  const StatusIcon = styles.statusIcon

  // Loading state
  if (loading) {
    return (
      <Card 
        className={cn("animate-pulse", className)}
        data-testid={testId}
        {...props}
      >
        <CardHeader className={cn(
          "flex flex-row items-center justify-between space-y-0",
          compact ? "pb-1" : "pb-2"
        )}>
          <div className="h-4 w-24 bg-muted rounded" />
          <div className="h-4 w-4 bg-muted rounded" />
        </CardHeader>
        <CardContent className={compact ? "p-3 pt-0" : undefined}>
          <div className={cn("h-8 w-16 bg-muted rounded mb-2", compact && "h-6")} />
          <div className="h-3 w-32 bg-muted rounded" />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card 
      className={cn(
        "transition-all duration-200",
        styles.card,
        interactive && "cursor-pointer hover:shadow-md hover:scale-[1.02]",
        onClick && "cursor-pointer hover:shadow-md",
        className
      )}
      onClick={onClick}
      data-testid={testId}
      {...props}
    >
      <CardHeader className={cn(
        "flex flex-row items-center justify-between space-y-0",
        compact ? "pb-1 p-3" : "pb-2"
      )}>
        <CardTitle className={cn(
          "font-medium text-muted-foreground",
          compact ? "text-xs" : "text-sm"
        )}>
          {title}
        </CardTitle>
        <div className="flex items-center gap-2">
          {Icon && (
            <Icon className={cn(
              styles.icon,
              compact ? "h-3 w-3" : "h-4 w-4"
            )} />
          )}
          {variant !== 'neutral' && (
            <StatusIcon className={cn(
              styles.icon,
              compact ? "h-3 w-3" : "h-4 w-4"
            )} />
          )}
        </div>
      </CardHeader>
      
      <CardContent className={compact ? "p-3 pt-0" : undefined}>
        <div className="flex items-baseline justify-between">
          <div className={cn(
            "font-bold",
            compact ? "text-lg" : "text-2xl"
          )}>
            {typeof value === 'number' ? value.toLocaleString() : value}
          </div>
          
          {trend && (
            <div className={cn("flex items-center text-xs", trendColor)}>
              {TrendIcon && <TrendIcon className="h-3 w-3 mr-1" />}
              <span className="font-medium">
                {trend.value > 0 ? '+' : ''}{trend.value}%
              </span>
            </div>
          )}
        </div>
        
        {description && (
          <CardDescription className={cn(
            "mt-2",
            compact && "text-xs"
          )}>
            {description}
          </CardDescription>
        )}
        
        {trend?.label && (
          <p className={cn(
            "text-muted-foreground mt-1",
            compact ? "text-[10px]" : "text-xs"
          )}>
            {trend.label}
          </p>
        )}
        
        <div className="flex items-center gap-2 mt-2">
          {variant !== 'neutral' && (
            <Badge 
              variant="secondary" 
              className={cn(styles.badge, compact && "text-[10px] px-1 py-0")}
            >
              {variant.charAt(0).toUpperCase() + variant.slice(1)}
            </Badge>
          )}
          
          {badge && (
            <Badge 
              variant={badge.variant || "outline"}
              className={compact ? "text-[10px] px-1 py-0" : undefined}
            >
              {badge.text}
            </Badge>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

// Preset status cards for common use cases (eliminates duplication)
export interface HealthStatusCardProps extends Omit<StandardizedStatusCardProps, 'variant' | 'value'> {
  isHealthy: boolean
  title?: string
}

export function HealthStatusCard({ 
  isHealthy, 
  title = "System Health",
  ...props 
}: HealthStatusCardProps) {
  return (
    <StandardizedStatusCard
      title={title}
      value={isHealthy ? "Healthy" : "Unhealthy"}
      variant={isHealthy ? "success" : "error"}
      {...props}
    />
  )
}

export interface CounterStatusCardProps extends Omit<StandardizedStatusCardProps, 'variant' | 'value'> {
  count: number
  threshold?: { warning?: number; error?: number }
}

export function CounterStatusCard({ 
  count, 
  threshold,
  ...props 
}: CounterStatusCardProps) {
  let variant: StatusCardBaseProps['variant'] = 'neutral'
  
  if (threshold) {
    if (threshold.error !== undefined && count >= threshold.error) {
      variant = 'error'
    } else if (threshold.warning !== undefined && count >= threshold.warning) {
      variant = 'warning'
    } else {
      variant = 'success'
    }
  }

  return (
    <StandardizedStatusCard
      value={count}
      variant={variant}
      {...props}
    />
  )
}

export interface PercentageStatusCardProps extends Omit<StandardizedStatusCardProps, 'variant' | 'value'> {
  percentage: number
}

export function PercentageStatusCard({ 
  percentage,
  ...props 
}: PercentageStatusCardProps) {
  let variant: StatusCardBaseProps['variant'] = 'neutral'
  
  if (percentage >= 90) {
    variant = 'success'
  } else if (percentage >= 70) {
    variant = 'warning'
  } else {
    variant = 'error'
  }

  return (
    <StandardizedStatusCard
      value={`${percentage}%`}
      variant={variant}
      {...props}
    />
  )
}

export interface ConnectionStatusCardProps extends Omit<StandardizedStatusCardProps, 'variant' | 'value'> {
  connected: boolean
  lastSeen?: string
}

export function ConnectionStatusCard({
  connected,
  lastSeen,
  title = "Connection Status",
  ...props
}: ConnectionStatusCardProps) {
  return (
    <StandardizedStatusCard
      title={title}
      value={connected ? "Connected" : "Disconnected"}
      variant={connected ? "success" : "error"}
      description={lastSeen ? `Last seen: ${lastSeen}` : undefined}
      {...props}
    />
  )
}

// Export the main component as default for backward compatibility
export default StandardizedStatusCard