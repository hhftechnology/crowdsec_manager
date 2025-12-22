import * as React from "react"
import { TrendingUp, TrendingDown, Minus } from "lucide-react"
import { cn } from "@/lib/utils"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"

export interface StatusCardProps {
  title: string
  value: string | number
  description?: string
  icon?: React.ComponentType<{ className?: string }>
  status?: 'success' | 'warning' | 'error' | 'info' | 'neutral'
  trend?: {
    value: number
    label: string
    direction: 'up' | 'down' | 'neutral'
  }
  loading?: boolean
  className?: string
  onClick?: () => void
}

const statusStyles = {
  success: {
    card: "border-green-200 bg-green-50/50 dark:border-green-800 dark:bg-green-950/50",
    icon: "text-green-600 dark:text-green-400",
    badge: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300"
  },
  warning: {
    card: "border-yellow-200 bg-yellow-50/50 dark:border-yellow-800 dark:bg-yellow-950/50",
    icon: "text-yellow-600 dark:text-yellow-400",
    badge: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300"
  },
  error: {
    card: "border-red-200 bg-red-50/50 dark:border-red-800 dark:bg-red-950/50",
    icon: "text-red-600 dark:text-red-400",
    badge: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300"
  },
  info: {
    card: "border-blue-200 bg-blue-50/50 dark:border-blue-800 dark:bg-blue-950/50",
    icon: "text-blue-600 dark:text-blue-400",
    badge: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300"
  },
  neutral: {
    card: "",
    icon: "text-muted-foreground",
    badge: "bg-muted text-muted-foreground"
  }
}

const trendIcons = {
  up: TrendingUp,
  down: TrendingDown,
  neutral: Minus
}

const trendColors = {
  up: "text-green-600 dark:text-green-400",
  down: "text-red-600 dark:text-red-400",
  neutral: "text-muted-foreground"
}

export function StatusCard({
  title,
  value,
  description,
  icon: Icon,
  status = 'neutral',
  trend,
  loading = false,
  className,
  onClick
}: StatusCardProps) {
  const styles = statusStyles[status]
  const TrendIcon = trend ? trendIcons[trend.direction] : null
  const trendColor = trend ? trendColors[trend.direction] : ""

  if (loading) {
    return (
      <Card className={cn("animate-pulse", className)}>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <div className="h-4 w-24 bg-muted rounded" />
          <div className="h-4 w-4 bg-muted rounded" />
        </CardHeader>
        <CardContent>
          <div className="h-8 w-16 bg-muted rounded mb-2" />
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
        onClick && "cursor-pointer hover:shadow-md",
        className
      )}
      onClick={onClick}
    >
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {title}
        </CardTitle>
        {Icon && (
          <Icon className={cn("h-4 w-4", styles.icon)} />
        )}
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline justify-between">
          <div className="text-2xl font-bold">
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
          <CardDescription className="mt-2">
            {description}
          </CardDescription>
        )}
        
        {trend?.label && (
          <p className="text-xs text-muted-foreground mt-1">
            {trend.label}
          </p>
        )}
        
        {status !== 'neutral' && (
          <Badge 
            variant="secondary" 
            className={cn("mt-2", styles.badge)}
          >
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </Badge>
        )}
      </CardContent>
    </Card>
  )
}

// Preset status cards for common use cases
export function HealthStatusCard({ 
  isHealthy, 
  title = "System Health",
  ...props 
}: Omit<StatusCardProps, 'status' | 'value'> & { 
  isHealthy: boolean 
  title?: string 
}) {
  return (
    <StatusCard
      title={title}
      value={isHealthy ? "Healthy" : "Unhealthy"}
      status={isHealthy ? "success" : "error"}
      {...props}
    />
  )
}

export function CounterStatusCard({ 
  count, 
  title,
  threshold,
  ...props 
}: Omit<StatusCardProps, 'status' | 'value'> & { 
  count: number
  threshold?: { warning?: number; error?: number }
}) {
  let status: StatusCardProps['status'] = 'neutral'
  
  if (threshold) {
    if (threshold.error !== undefined && count >= threshold.error) {
      status = 'error'
    } else if (threshold.warning !== undefined && count >= threshold.warning) {
      status = 'warning'
    } else {
      status = 'success'
    }
  }

  return (
    <StatusCard
      title={title}
      value={count}
      status={status}
      {...props}
    />
  )
}

export function PercentageStatusCard({ 
  percentage, 
  title,
  ...props 
}: Omit<StatusCardProps, 'status' | 'value'> & { 
  percentage: number 
}) {
  let status: StatusCardProps['status'] = 'neutral'
  
  if (percentage >= 90) {
    status = 'success'
  } else if (percentage >= 70) {
    status = 'warning'
  } else {
    status = 'error'
  }

  return (
    <StatusCard
      title={title}
      value={`${percentage}%`}
      status={status}
      {...props}
    />
  )
}