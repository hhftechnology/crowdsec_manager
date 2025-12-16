import { Link, useLocation } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { useTheme } from '@/components/ThemeProvider.tsx'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  Shield,
  PanelLeftClose,
  PanelLeftOpen,
  Moon,
  Sun,
} from 'lucide-react'
import { ProxyType, Feature } from '@/lib/proxy-types'
import { getNavigationForProxy, getQuickActionsForProxy } from './ProxyAwareNavigation'
import { QuickActionsPanel } from './QuickActionsPanel'

interface EnhancedSidebarProps {
  proxyType: ProxyType
  supportedFeatures: Feature[]
  isCollapsed: boolean
  setIsCollapsed: (collapsed: boolean) => void
}

interface NavigationItemProps {
  item: {
    name: string
    href: string
    icon: any
    available: boolean
    tooltip?: string
  }
  isActive: boolean
  isCollapsed: boolean
}

function NavigationItem({ item, isActive, isCollapsed }: NavigationItemProps) {
  const Icon = item.icon
  
  if (isCollapsed) {
    return (
      <TooltipProvider>
        <Tooltip delayDuration={0}>
          <TooltipTrigger asChild>
            <Link
              to={item.href}
              className={cn(
                "flex items-center justify-center p-2 rounded-md transition-colors",
                isActive
                  ? "bg-primary text-primary-foreground"
                  : item.available
                  ? "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                  : "text-muted-foreground/50 cursor-not-allowed",
                !item.available && "opacity-50"
              )}
              onClick={(e) => !item.available && e.preventDefault()}
            >
              <Icon className="h-5 w-5" />
            </Link>
          </TooltipTrigger>
          <TooltipContent side="right">
            <div className="flex flex-col gap-1">
              <span>{item.name}</span>
              {!item.available && item.tooltip && (
                <span className="text-xs text-muted-foreground">{item.tooltip}</span>
              )}
            </div>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    )
  }

  return (
    <Link
      to={item.href}
      className={cn(
        "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
        isActive
          ? "bg-primary text-primary-foreground"
          : item.available
          ? "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
          : "text-muted-foreground/50 cursor-not-allowed",
        !item.available && "opacity-50"
      )}
      onClick={(e) => !item.available && e.preventDefault()}
    >
      <Icon className="h-4 w-4" />
      <span className="flex-1">{item.name}</span>
      {!item.available && (
        <Badge variant="secondary" className="text-xs">
          N/A
        </Badge>
      )}
    </Link>
  )
}

export function EnhancedSidebar({ 
  proxyType, 
  supportedFeatures, 
  isCollapsed, 
  setIsCollapsed 
}: EnhancedSidebarProps) {
  const location = useLocation()
  const { theme, setTheme } = useTheme()
  
  const navigation = getNavigationForProxy(proxyType, supportedFeatures)
  const quickActions = getQuickActionsForProxy(proxyType, supportedFeatures)

  const toggleTheme = () => {
    setTheme(theme === "dark" ? "light" : "dark")
  }

  return (
    <div
      className={cn(
        "flex flex-col h-full bg-card text-card-foreground border-r transition-all duration-300",
        isCollapsed ? "w-16" : "w-64"
      )}
    >
      {/* Header with Proxy Type */}
      <div className={cn(
        "flex items-center p-4 border-b", 
        isCollapsed ? "justify-center" : "justify-between"
      )}>
        {!isCollapsed && (
          <div className="flex items-center gap-2 font-semibold text-lg">
            <Shield className="h-6 w-6 text-primary" />
            <div className="flex flex-col">
              <span>CrowdSec Manager</span>
              <Badge variant="outline" className="text-xs w-fit mt-1">
                {proxyType.charAt(0).toUpperCase() + proxyType.slice(1)} Mode
              </Badge>
            </div>
          </div>
        )}
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setIsCollapsed(!isCollapsed)}
          className={cn("h-8 w-8", isCollapsed && "w-full")}
        >
          {isCollapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
        </Button>
      </div>

      {/* Navigation with Feature Availability */}
      <ScrollArea className="flex-1 px-2 py-4">
        <div className="space-y-6">
          {navigation.map((group) => (
            <div key={group.title}>
              {!isCollapsed && (
                <h4 className="mb-2 px-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  {group.title}
                </h4>
              )}
              <div className="space-y-1">
                {group.items.map((item) => {
                  const isActive = location.pathname === item.href
                  
                  return (
                    <NavigationItem 
                      key={item.name}
                      item={item}
                      isActive={isActive}
                      isCollapsed={isCollapsed}
                    />
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      </ScrollArea>

      {/* Quick Actions Panel */}
      {!isCollapsed && (
        <div className="p-4 border-t">
          <QuickActionsPanel 
            proxyType={proxyType} 
            supportedFeatures={supportedFeatures}
            actions={quickActions}
          />
        </div>
      )}

      {/* Footer with Theme Toggle */}
      <div className="p-4 border-t">
        <Button
          variant="ghost"
          size={isCollapsed ? "icon" : "default"}
          onClick={toggleTheme}
          className={cn("w-full justify-start", isCollapsed && "justify-center")}
        >
          {theme === "dark" ? (
            <Sun className="h-4 w-4" />
          ) : (
            <Moon className="h-4 w-4" />
          )}
          {!isCollapsed && <span className="ml-2">Toggle Theme</span>}
        </Button>
      </div>
    </div>
  )
}