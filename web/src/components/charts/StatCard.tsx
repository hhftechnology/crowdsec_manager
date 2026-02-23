import { ArrowDown, ArrowUp } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { cn } from '@/lib/utils'

interface StatCardProps {
  title: string
  value: string | number
  description?: string
  icon?: React.ReactNode
  /** Trend indicator. Positive `value` shows green up arrow, negative shows red down arrow. */
  trend?: { value: number; label: string }
  loading?: boolean
  className?: string
}

export default function StatCard({
  title,
  value,
  description,
  icon,
  trend,
  loading = false,
  className,
}: StatCardProps) {
  if (loading) {
    return (
      <Card className={cn('animate-fade-in', className)}>
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            <div className="h-4 w-24 animate-pulse rounded bg-muted" />
            <div className="h-8 w-8 animate-pulse rounded bg-muted" />
          </div>
          <div className="mt-3 h-8 w-20 animate-pulse rounded bg-muted" />
          <div className="mt-2 h-3 w-32 animate-pulse rounded bg-muted" />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className={cn('animate-fade-in', className)}>
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <p className="text-sm font-medium text-muted-foreground">{title}</p>
          {icon && (
            <div className="text-muted-foreground">{icon}</div>
          )}
        </div>

        <p className="mt-2 text-2xl font-bold">{value}</p>

        {trend && (
          <div className="mt-1 flex items-center gap-1 text-xs">
            {trend.value >= 0 ? (
              <ArrowUp className="h-3 w-3 text-emerald-600 dark:text-emerald-400" />
            ) : (
              <ArrowDown className="h-3 w-3 text-destructive" />
            )}
            <span
              className={cn(
                'font-medium',
                trend.value >= 0
                  ? 'text-emerald-600 dark:text-emerald-400'
                  : 'text-destructive',
              )}
            >
              {Math.abs(trend.value)}%
            </span>
            <span className="text-muted-foreground">{trend.label}</span>
          </div>
        )}

        {description && (
          <p className="mt-1 text-xs text-muted-foreground">{description}</p>
        )}
      </CardContent>
    </Card>
  )
}
