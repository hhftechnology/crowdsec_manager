import React from 'react'
import { cn } from '@/lib/utils'
import { useBreakpoints } from '@/hooks/useMediaQuery'
import { ResponsiveGrid, ResponsiveGridItem } from '@/components/ui/responsive-grid'
import { ResponsiveCard, ResponsiveCardContent, ResponsiveCardHeader, ResponsiveCardTitle } from '@/components/ui/responsive-card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { 
  Activity, 
  Shield, 
  Network, 
  Target, 
  AlertTriangle,
  TrendingUp,
  Clock,
  CheckCircle,
  XCircle,
  Zap
} from 'lucide-react'

interface DashboardMetric {
  title: string
  value: string | number
  change?: string
  trend?: 'up' | 'down' | 'neutral'
  icon: React.ComponentType<any>
  color?: 'green' | 'red' | 'blue' | 'yellow' | 'purple'
}

interface ResponsiveDashboardProps {
  metrics?: DashboardMetric[]
  className?: string
}

const defaultMetrics: DashboardMetric[] = [
  {
    title: 'Active Decisions',
    value: 1247,
    change: '+12%',
    trend: 'up',
    icon: Target,
    color: 'red'
  },
  {
    title: 'Blocked IPs',
    value: 892,
    change: '+8%',
    trend: 'up',
    icon: Shield,
    color: 'green'
  },
  {
    title: 'Proxy Status',
    value: 'Healthy',
    icon: Network,
    color: 'blue'
  },
  {
    title: 'Alerts (24h)',
    value: 34,
    change: '-15%',
    trend: 'down',
    icon: AlertTriangle,
    color: 'yellow'
  }
]

function MetricCard({ metric, isMobile }: { metric: DashboardMetric; isMobile: boolean }) {
  const Icon = metric.icon
  
  const getColorClasses = (color?: string) => {
    switch (color) {
      case 'green':
        return 'text-green-600 bg-green-50 border-green-200'
      case 'red':
        return 'text-red-600 bg-red-50 border-red-200'
      case 'blue':
        return 'text-blue-600 bg-blue-50 border-blue-200'
      case 'yellow':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200'
      case 'purple':
        return 'text-purple-600 bg-purple-50 border-purple-200'
      default:
        return 'text-primary bg-primary/10 border-primary/20'
    }
  }
  
  const getTrendIcon = (trend?: string) => {
    switch (trend) {
      case 'up':
        return <TrendingUp className="h-3 w-3 text-green-600" />
      case 'down':
        return <TrendingUp className="h-3 w-3 text-red-600 rotate-180" />
      default:
        return null
    }
  }
  
  return (
    <ResponsiveCard 
      variant="status" 
      touchOptimized={isMobile}
      className={cn(
        "border-l-4 transition-all duration-200",
        getColorClasses(metric.color),
        isMobile && "active:scale-98"
      )}
    >
      <ResponsiveCardContent spacing="tight">
        <div className="flex items-center justify-between">
          <div className="flex-1">
            <p className={cn(
              "text-muted-foreground font-medium",
              isMobile ? "text-sm" : "text-xs"
            )}>
              {metric.title}
            </p>
            <div className="flex items-center gap-2 mt-1">
              <p className={cn(
                "font-bold",
                isMobile ? "text-xl" : "text-2xl"
              )}>
                {metric.value}
              </p>
              {metric.change && (
                <div className="flex items-center gap-1">
                  {getTrendIcon(metric.trend)}
                  <span className={cn(
                    "text-xs font-medium",
                    metric.trend === 'up' ? "text-green-600" : 
                    metric.trend === 'down' ? "text-red-600" : 
                    "text-muted-foreground"
                  )}>
                    {metric.change}
                  </span>
                </div>
              )}
            </div>
          </div>
          <div className={cn(
            "rounded-full p-2",
            getColorClasses(metric.color)
          )}>
            <Icon className={cn(isMobile ? "h-5 w-5" : "h-4 w-4")} />
          </div>
        </div>
      </ResponsiveCardContent>
    </ResponsiveCard>
  )
}

function QuickActions({ isMobile }: { isMobile: boolean }) {
  const actions = [
    { label: 'Add IP to Whitelist', icon: Shield, variant: 'default' as const },
    { label: 'View Recent Alerts', icon: AlertTriangle, variant: 'outline' as const },
    { label: 'Check System Health', icon: Activity, variant: 'outline' as const },
    { label: 'Manage Decisions', icon: Target, variant: 'outline' as const },
  ]
  
  return (
    <ResponsiveCard>
      <ResponsiveCardHeader compact>
        <ResponsiveCardTitle size="md">Quick Actions</ResponsiveCardTitle>
      </ResponsiveCardHeader>
      <ResponsiveCardContent spacing="tight">
        <div className={cn(
          "grid gap-2",
          isMobile ? "grid-cols-1" : "grid-cols-2"
        )}>
          {actions.map((action, index) => {
            const Icon = action.icon
            return (
              <Button
                key={index}
                variant={action.variant}
                size={isMobile ? "default" : "sm"}
                className={cn(
                  "justify-start gap-2",
                  isMobile && "min-h-[48px]"
                )}
              >
                <Icon className="h-4 w-4" />
                <span className={cn(isMobile && "text-sm")}>{action.label}</span>
              </Button>
            )
          })}
        </div>
      </ResponsiveCardContent>
    </ResponsiveCard>
  )
}

function SystemStatus({ isMobile }: { isMobile: boolean }) {
  const services = [
    { name: 'CrowdSec Engine', status: 'running', uptime: '7d 12h' },
    { name: 'Traefik Proxy', status: 'running', uptime: '7d 12h' },
    { name: 'Bouncer Plugin', status: 'running', uptime: '7d 12h' },
    { name: 'LAPI Connection', status: 'connected', uptime: '7d 12h' },
  ]
  
  return (
    <ResponsiveCard>
      <ResponsiveCardHeader compact>
        <ResponsiveCardTitle size="md">System Status</ResponsiveCardTitle>
      </ResponsiveCardHeader>
      <ResponsiveCardContent spacing="tight">
        <div className="space-y-3">
          {services.map((service, index) => (
            <div key={index} className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {service.status === 'running' || service.status === 'connected' ? (
                  <CheckCircle className="h-4 w-4 text-green-600" />
                ) : (
                  <XCircle className="h-4 w-4 text-red-600" />
                )}
                <span className={cn(
                  "font-medium",
                  isMobile ? "text-sm" : "text-xs"
                )}>
                  {service.name}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Badge 
                  variant={service.status === 'running' || service.status === 'connected' ? 'default' : 'destructive'}
                  className="text-xs"
                >
                  {service.status}
                </Badge>
                {!isMobile && (
                  <span className="text-xs text-muted-foreground">
                    {service.uptime}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </ResponsiveCardContent>
    </ResponsiveCard>
  )
}

function RecentActivity({ isMobile }: { isMobile: boolean }) {
  const activities = [
    { action: 'IP 192.168.1.100 blocked', time: '2 min ago', type: 'block' },
    { action: 'Scenario updated: ssh-bruteforce', time: '15 min ago', type: 'update' },
    { action: 'New decision: ban 10.0.0.5', time: '32 min ago', type: 'decision' },
    { action: 'Whitelist updated', time: '1 hour ago', type: 'whitelist' },
  ]
  
  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'block':
        return <Shield className="h-3 w-3 text-red-600" />
      case 'update':
        return <Zap className="h-3 w-3 text-blue-600" />
      case 'decision':
        return <Target className="h-3 w-3 text-yellow-600" />
      case 'whitelist':
        return <CheckCircle className="h-3 w-3 text-green-600" />
      default:
        return <Activity className="h-3 w-3 text-muted-foreground" />
    }
  }
  
  return (
    <ResponsiveCard>
      <ResponsiveCardHeader compact>
        <ResponsiveCardTitle size="md">Recent Activity</ResponsiveCardTitle>
      </ResponsiveCardHeader>
      <ResponsiveCardContent spacing="tight">
        <div className="space-y-3">
          {activities.map((activity, index) => (
            <div key={index} className="flex items-start gap-3">
              <div className="mt-1">
                {getActivityIcon(activity.type)}
              </div>
              <div className="flex-1 min-w-0">
                <p className={cn(
                  "font-medium truncate",
                  isMobile ? "text-sm" : "text-xs"
                )}>
                  {activity.action}
                </p>
                <p className="text-xs text-muted-foreground flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {activity.time}
                </p>
              </div>
            </div>
          ))}
        </div>
      </ResponsiveCardContent>
    </ResponsiveCard>
  )
}

export function ResponsiveDashboard({ 
  metrics = defaultMetrics, 
  className 
}: ResponsiveDashboardProps) {
  const { isMobile, isTablet, isDesktop } = useBreakpoints()
  
  return (
    <div className={cn("w-full space-y-6", className)}>
      {/* Metrics Grid */}
      <ResponsiveGrid
        cols={{
          mobile: 1,
          tablet: 2,
          desktop: 4,
          largeDesktop: 4
        }}
        gap="md"
      >
        {metrics.map((metric, index) => (
          <ResponsiveGridItem key={index}>
            <MetricCard metric={metric} isMobile={isMobile} />
          </ResponsiveGridItem>
        ))}
      </ResponsiveGrid>
      
      {/* Main Content Grid */}
      <ResponsiveGrid
        cols={{
          mobile: 1,
          tablet: 2,
          desktop: 3,
          largeDesktop: 3
        }}
        gap="lg"
      >
        {/* Quick Actions - Full width on mobile, spans 1 col on tablet+ */}
        <ResponsiveGridItem
          span={{
            mobile: 1,
            tablet: 1,
            desktop: 1
          }}
        >
          <QuickActions isMobile={isMobile} />
        </ResponsiveGridItem>
        
        {/* System Status */}
        <ResponsiveGridItem
          span={{
            mobile: 1,
            tablet: 1,
            desktop: 1
          }}
        >
          <SystemStatus isMobile={isMobile} />
        </ResponsiveGridItem>
        
        {/* Recent Activity - Full width on mobile and tablet */}
        <ResponsiveGridItem
          span={{
            mobile: 1,
            tablet: 2,
            desktop: 1
          }}
        >
          <RecentActivity isMobile={isMobile} />
        </ResponsiveGridItem>
      </ResponsiveGrid>
    </div>
  )
}

export default ResponsiveDashboard