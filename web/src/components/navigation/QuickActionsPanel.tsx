import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ProxyType, Feature } from '@/lib/proxy-types'
import { NavigationItem } from '@/lib/proxy-types'
import { Link } from 'react-router-dom'
import { Zap } from 'lucide-react'

interface QuickActionsPanelProps {
  proxyType: ProxyType
  supportedFeatures: Feature[]
  actions: NavigationItem[]
  className?: string
}

export function QuickActionsPanel({ 
  proxyType, 
  supportedFeatures, 
  actions,
  className 
}: QuickActionsPanelProps) {
  const availableActions = actions.filter(action => action.available)
  
  if (availableActions.length === 0) {
    return null
  }

  return (
    <Card className={className}>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Zap className="h-4 w-4" />
          Quick Actions
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {availableActions.slice(0, 3).map((action) => {
          const Icon = action.icon
          return (
            <Button
              key={action.name}
              asChild
              variant="outline"
              size="sm"
              className="w-full justify-start"
            >
              <Link to={action.href}>
                <Icon className="h-3 w-3 mr-2" />
                {action.name}
              </Link>
            </Button>
          )
        })}
        
        {availableActions.length > 3 && (
          <div className="pt-2 border-t">
            <Badge variant="secondary" className="text-xs">
              +{availableActions.length - 3} more actions
            </Badge>
          </div>
        )}
        
        <div className="pt-2 text-xs text-muted-foreground">
          Available for {proxyType.charAt(0).toUpperCase() + proxyType.slice(1)}
        </div>
      </CardContent>
    </Card>
  )
}