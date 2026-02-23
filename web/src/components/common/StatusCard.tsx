import { cn } from '@/lib/utils'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { LucideIcon } from 'lucide-react'

type StatusCardVariant = 'default' | 'success' | 'warning' | 'error'

interface StatusCardProps {
  title: string
  value: string | number
  description?: string
  icon?: LucideIcon
  variant?: StatusCardVariant
  className?: string
}

const variantStyles: Record<StatusCardVariant, { icon: string; border: string }> = {
  default: {
    icon: 'text-muted-foreground',
    border: '',
  },
  success: {
    icon: 'text-emerald-600 dark:text-emerald-400',
    border: 'border-emerald-500/20',
  },
  warning: {
    icon: 'text-amber-600 dark:text-amber-400',
    border: 'border-amber-500/20',
  },
  error: {
    icon: 'text-destructive',
    border: 'border-destructive/20',
  },
}

function StatusCard({
  title,
  value,
  description,
  icon: Icon,
  variant = 'default',
  className,
}: StatusCardProps) {
  const styles = variantStyles[variant]

  return (
    <Card className={cn(styles.border, className)}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        {Icon && <Icon className={cn('h-4 w-4', styles.icon)} />}
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        {description && (
          <p className="text-xs text-muted-foreground">{description}</p>
        )}
      </CardContent>
    </Card>
  )
}

export { StatusCard }
export type { StatusCardProps, StatusCardVariant }
