import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { ProxyType, ProxyStatus } from '@/lib/proxy-types'
import { 
  Network, 
  Server, 
  Shield, 
  Activity, 
  Zap, 
  Database,
  CheckCircle,
  XCircle,
  AlertTriangle
} from 'lucide-react'

interface ProxyStatusIndicatorProps {
  proxyStatus: ProxyStatus
  className?: string
  showDetails?: boolean
}

const PROXY_ICONS: Record<ProxyType, any> = {
  traefik: Network,
  nginx: Server,
  caddy: Shield,
  haproxy: Activity,
  zoraxy: Zap,
  standalone: Database
}

const STATUS_COLORS = {
  healthy: 'bg-green-500',
  unhealthy: 'bg-red-500',
  warning: 'bg-yellow-500',
  unknown: 'bg-gray-500'
}

const STATUS_ICONS = {
  healthy: CheckCircle,
  unhealthy: XCircle,
  warning: AlertTriangle,
  unknown: AlertTriangle
}

export function ProxyStatusIndicator({ 
  proxyStatus, 
  className,
  showDetails = true 
}: ProxyStatusIndicatorProps) {
  const Icon = PROXY_ICONS[proxyStatus.type]
  const StatusIcon = STATUS_ICONS[proxyStatus.healthStatus]
  
  const getConnectionStatus = () => {
    if (!proxyStatus.running) return 'Stopped'
    if (!proxyStatus.connected) return 'Disconnected'
    return 'Connected'
  }

  const getStatusVariant = () => {
    if (!proxyStatus.running) return 'destructive'
    if (!proxyStatus.connected) return 'secondary'
    return 'default'
  }

  return (
    <div className={cn(
      "flex items-center gap-2 px-3 py-1 rounded-full bg-muted",
      className
    )}>
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4 text-primary" />
        <div className={cn(
          "w-2 h-2 rounded-full",
          proxyStatus.running && proxyStatus.connected 
            ? STATUS_COLORS.healthy 
            : STATUS_COLORS.unhealthy
        )} />
      </div>
      
      <span className="text-sm font-medium capitalize">
        {proxyStatus.type}
      </span>
      
      {showDetails && (
        <>
          <Badge variant={getStatusVariant()} className="text-xs">
            {getConnectionStatus()}
          </Badge>
          
          <div className="flex items-center gap-1">
            <StatusIcon className={cn(
              "h-3 w-3",
              proxyStatus.healthStatus === 'healthy' ? 'text-green-500' :
              proxyStatus.healthStatus === 'unhealthy' ? 'text-red-500' :
              proxyStatus.healthStatus === 'warning' ? 'text-yellow-500' :
              'text-gray-500'
            )} />
            <span className="text-xs text-muted-foreground capitalize">
              {proxyStatus.healthStatus}
            </span>
          </div>
        </>
      )}
    </div>
  )
}