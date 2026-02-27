import { cn } from '@/lib/utils'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { CheckCircle2, AlertTriangle, XCircle, HelpCircle } from 'lucide-react'

type StatusLevel = 'healthy' | 'warning' | 'error' | 'unknown'

interface StatusItem {
  name: string
  status: StatusLevel
  message?: string
}

interface StatusDashboardProps {
  items: StatusItem[]
  className?: string
}

const statusConfig: Record<StatusLevel, {
  icon: typeof CheckCircle2
  badgeVariant: 'success' | 'warning' | 'destructive' | 'secondary'
  iconClass: string
  label: string
}> = {
  healthy: {
    icon: CheckCircle2,
    badgeVariant: 'success',
    iconClass: 'text-emerald-600 dark:text-emerald-400',
    label: 'Healthy',
  },
  warning: {
    icon: AlertTriangle,
    badgeVariant: 'warning',
    iconClass: 'text-amber-600 dark:text-amber-400',
    label: 'Warning',
  },
  error: {
    icon: XCircle,
    badgeVariant: 'destructive',
    iconClass: 'text-destructive',
    label: 'Error',
  },
  unknown: {
    icon: HelpCircle,
    badgeVariant: 'secondary',
    iconClass: 'text-muted-foreground',
    label: 'Unknown',
  },
}

function StatusDashboard({ items, className }: StatusDashboardProps) {
  return (
    <div className={cn('grid gap-4 sm:grid-cols-2 lg:grid-cols-3', className)}>
      {items.map((item) => {
        const config = statusConfig[item.status]
        const Icon = config.icon

        return (
          <Card key={item.name}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">{item.name}</CardTitle>
              <Badge variant={config.badgeVariant}>{config.label}</Badge>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2">
                <Icon className={cn('h-5 w-5', config.iconClass)} />
                <span className="text-sm text-muted-foreground">
                  {item.message ?? `Service is ${config.label.toLowerCase()}`}
                </span>
              </div>
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}

export { StatusDashboard }
export type { StatusDashboardProps, StatusItem, StatusLevel }
