import { ContainerInfo, ContainerRole } from '@/lib/deployment-types'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { Container, Shield, Network, Plug, Activity, CheckCircle2, AlertCircle, AlertTriangle } from 'lucide-react'
import { useBreakpoints } from '@/hooks/useMediaQuery'

interface ContainerStatusListProps {
  containers: ContainerInfo[]
  isLoading?: boolean
}

interface ContainerGroupProps {
  title: string
  containers: ContainerInfo[]
  icon: React.ElementType
}

function ContainerGroup({ title, containers, icon: Icon }: ContainerGroupProps) {
  const { isMobile, needsTouchOptimization } = useBreakpoints()

  if (containers.length === 0) return null

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2">
        <Icon className="h-4 w-4" />
        {title}
      </h3>
      <div className="grid gap-2">
        {containers.map(container => (
          <div
            key={container.id}
            className={cn(
              "flex items-center justify-between rounded-lg border bg-card transition-colors",
              isMobile ? "p-3" : "p-3",
              needsTouchOptimization && "min-h-[44px] active:bg-accent/50"
            )}
          >
            <div className="flex items-center gap-3 min-w-0 flex-1">
              <Container className="h-4 w-4 text-muted-foreground flex-shrink-0" />
              <div className="min-w-0 flex-1">
                <p className={cn(
                  "font-medium truncate",
                  isMobile ? "text-sm" : "text-base"
                )}>
                  {container.name}
                </p>
                <div className="flex items-center gap-2">
                  <p className={cn(
                    "text-muted-foreground truncate font-mono",
                    isMobile ? "text-xs" : "text-sm"
                  )}>
                    {container.id.substring(0, 12)}
                  </p>
                  {container.image && (
                    <p className="text-xs text-muted-foreground truncate hidden sm:block max-w-[200px]">
                      {container.image}
                    </p>
                  )}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
               {/* Minimal status indicator for mobile */}
              <Badge
                variant={container.running ? 'default' : 'destructive'}
                className={cn(isMobile ? "text-[10px] px-1.5 h-5" : "")}
              >
                {container.status}
              </Badge>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export function ContainerStatusList({ containers, isLoading }: ContainerStatusListProps) {
  const { isMobile } = useBreakpoints()
  
  const proxyContainers = containers.filter(c => c.role === ContainerRole.PROXY)
  const securityContainers = containers.filter(c => c.role === ContainerRole.SECURITY)
  const addonContainers = containers.filter(c => c.role === ContainerRole.ADDON)
  const otherContainers = containers.filter(c => 
    c.role !== ContainerRole.PROXY && 
    c.role !== ContainerRole.SECURITY && 
    c.role !== ContainerRole.ADDON
  )

  const allRunning = containers.every(c => c.running)
  const runningCount = containers.filter(c => c.running).length

  return (
    <Card className="transition-all duration-200">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className={cn(
              "flex items-center gap-2",
              isMobile ? "text-lg" : "text-xl"
            )}>
              {isLoading ? (
                <Activity className="h-5 w-5 animate-pulse" />
              ) : allRunning && containers.length > 0 ? (
                <CheckCircle2 className="h-5 w-5 text-green-500" />
              ) : (
                <AlertCircle className="h-5 w-5 text-red-500" />
              )}
              System Health
            </CardTitle>
            <CardDescription>
              {isLoading 
                ? 'Checking container status...' 
                : `${runningCount} of ${containers.length} containers running`}
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          <ContainerGroup title="Proxy Services" containers={proxyContainers} icon={Network} />
          <ContainerGroup title="Security Engines" containers={securityContainers} icon={Shield} />
          <ContainerGroup title="Addons & Extensions" containers={addonContainers} icon={Plug} />
          <ContainerGroup title="Other Containers" containers={otherContainers} icon={Container} />
          
          {!isLoading && containers.length === 0 && (
            <div className="text-center py-8 text-muted-foreground">
              <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No containers detected from the current deployment stack.</p>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
