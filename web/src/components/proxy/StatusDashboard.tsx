import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { ProxyType, ProxyHealthData } from '@/lib/proxy-types'
import {
  Network,
  Shield,
  Activity,
  Target,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock
} from 'lucide-react'

interface StatusCardProps {
  title: string
  value: string | number
  icon: any
  variant: 'success' | 'error' | 'warning' | 'info'
  description?: string
  className?: string
}

interface StatusDashboardProps {
  proxyType: ProxyType
  proxyStatus: {
    running: boolean
    connected: boolean
  }
  crowdsecStatus: {
    running: boolean
    enrolled: boolean
  }
  bouncerStatus: {
    connected: boolean
    lastSeen?: string
  }
  decisions: {
    count: number
    active: number
  }
  className?: string
}

const STATUS_VARIANTS = {
  success: {
    badge: 'default',
    icon: CheckCircle,
    iconColor: 'text-green-500'
  },
  error: {
    badge: 'destructive',
    icon: XCircle,
    iconColor: 'text-red-500'
  },
  warning: {
    badge: 'secondary',
    icon: AlertTriangle,
    iconColor: 'text-yellow-500'
  },
  info: {
    badge: 'outline',
    icon: Activity,
    iconColor: 'text-blue-500'
  }
} as const

function StatusCard({ 
  title, 
  value, 
  icon: Icon, 
  variant, 
  description, 
  className 
}: StatusCardProps) {
  const config = STATUS_VARIANTS[variant]
  const StatusIcon = config.icon
  
  return (
    <Card className={cn("transition-all hover:shadow-md", className)}>
      <CardContent className="p-4">
        <div className="flex items-center justify-between mb-2">
          <Icon className="h-5 w-5 text-muted-foreground" />
          <StatusIcon className={cn("h-4 w-4", config.iconColor)} />
        </div>
        
        <div className="space-y-1">
          <p className="text-2xl font-bold">{value}</p>
          <p className="text-sm font-medium">{title}</p>
          {description && (
            <p className="text-xs text-muted-foreground">{description}</p>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

export function StatusDashboard({
  proxyType,
  proxyStatus,
  crowdsecStatus,
  bouncerStatus,
  decisions,
  className
}: StatusDashboardProps) {
  const getProxyStatusVariant = (): 'success' | 'error' | 'warning' => {
    if (proxyStatus.running && proxyStatus.connected) return 'success'
    if (proxyStatus.running && !proxyStatus.connected) return 'warning'
    return 'error'
  }

  const getCrowdSecStatusVariant = (): 'success' | 'error' | 'warning' => {
    if (crowdsecStatus.running && crowdsecStatus.enrolled) return 'success'
    if (crowdsecStatus.running && !crowdsecStatus.enrolled) return 'warning'
    return 'error'
  }

  const getBouncerStatusVariant = (): 'success' | 'error' | 'warning' => {
    if (bouncerStatus.connected) return 'success'
    return 'warning'
  }

  const getProxyStatusText = () => {
    if (proxyStatus.running && proxyStatus.connected) return 'Running'
    if (proxyStatus.running && !proxyStatus.connected) return 'Disconnected'
    return 'Stopped'
  }

  const getCrowdSecStatusText = () => {
    if (crowdsecStatus.running && crowdsecStatus.enrolled) return 'Active'
    if (crowdsecStatus.running && !crowdsecStatus.enrolled) return 'Not Enrolled'
    return 'Inactive'
  }

  const getBouncerStatusText = () => {
    return bouncerStatus.connected ? 'Connected' : 'Disconnected'
  }

  return (
    <div className={cn(
      "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4",
      className
    )}>
      <StatusCard
        title="Proxy Status"
        value={getProxyStatusText()}
        icon={Network}
        variant={getProxyStatusVariant()}
        description={`${proxyType.charAt(0).toUpperCase() + proxyType.slice(1)} container`}
      />
      
      <StatusCard
        title="CrowdSec Status"
        value={getCrowdSecStatusText()}
        icon={Shield}
        variant={getCrowdSecStatusVariant()}
        description="Security engine"
      />
      
      <StatusCard
        title="Bouncer Status"
        value={getBouncerStatusText()}
        icon={Activity}
        variant={getBouncerStatusVariant()}
        description={bouncerStatus.lastSeen ? `Last seen: ${bouncerStatus.lastSeen}` : 'LAPI connection'}
      />
      
      <StatusCard
        title="Active Decisions"
        value={decisions.active}
        icon={Target}
        variant="info"
        description={`${decisions.count} total decisions`}
      />
    </div>
  )
}