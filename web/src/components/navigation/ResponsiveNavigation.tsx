import React, { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { useBreakpoints } from '@/hooks/useMediaQuery'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  Shield,
  Menu,
  X,
  ChevronDown,
  ChevronRight
} from 'lucide-react'
import { ProxyType, Feature } from '@/lib/proxy-types'
import { getNavigationForProxy } from './ProxyAwareNavigation'

interface ResponsiveNavigationProps {
  proxyType: ProxyType
  supportedFeatures: Feature[]
  className?: string
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
  isMobile: boolean
  isCollapsed: boolean
  onItemClick?: () => void
}

function NavigationItem({ item, isActive, isMobile, isCollapsed, onItemClick }: NavigationItemProps) {
  const Icon = item.icon
  
  const handleClick = () => {
    if (onItemClick) onItemClick()
  }
  
  if (isCollapsed && !isMobile) {
    return (
      <TooltipProvider>
        <Tooltip delayDuration={0}>
          <TooltipTrigger asChild>
            <Link
              to={item.href}
              onClick={handleClick}
              className={cn(
                "flex items-center justify-center p-2 rounded-md transition-colors",
                isActive
                  ? "bg-primary text-primary-foreground"
                  : item.available
                  ? "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                  : "text-muted-foreground/50 cursor-not-allowed",
                !item.available && "opacity-50"
              )}
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
      onClick={handleClick}
      className={cn(
        "flex items-center gap-3 rounded-md text-sm transition-colors",
        // Touch-friendly sizing
        isMobile ? "px-4 py-3 min-h-[48px]" : "px-3 py-2",
        isActive
          ? "bg-primary text-primary-foreground"
          : item.available
          ? "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
          : "text-muted-foreground/50 cursor-not-allowed",
        !item.available && "opacity-50"
      )}
    >
      <Icon className={cn(isMobile ? "h-5 w-5" : "h-4 w-4")} />
      <span className="flex-1">{item.name}</span>
      {!item.available && (
        <Badge variant="secondary" className="text-xs">
          N/A
        </Badge>
      )}
    </Link>
  )
}

interface NavigationGroupProps {
  group: {
    title: string
    items: any[]
  }
  isCollapsed: boolean
  isMobile: boolean
  onItemClick?: () => void
}

function NavigationGroup({ group, isCollapsed, isMobile, onItemClick }: NavigationGroupProps) {
  const location = useLocation()
  const [isExpanded, setIsExpanded] = useState(true)
  
  // Auto-collapse groups on mobile to save space
  useEffect(() => {
    if (isMobile) {
      const hasActiveItem = group.items.some(item => location.pathname === item.href)
      setIsExpanded(hasActiveItem)
    }
  }, [isMobile, group.items, location.pathname])
  
  return (
    <div>
      {!isCollapsed && (
        <div className="flex items-center justify-between mb-2 px-2">
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            {group.title}
          </h4>
          {isMobile && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsExpanded(!isExpanded)}
              className="h-6 w-6 p-0"
            >
              {isExpanded ? (
                <ChevronDown className="h-3 w-3" />
              ) : (
                <ChevronRight className="h-3 w-3" />
              )}
            </Button>
          )}
        </div>
      )}
      
      <div className={cn(
        "space-y-1 transition-all duration-200",
        isMobile && !isExpanded && "hidden"
      )}>
        {group.items.map((item) => {
          const isActive = location.pathname === item.href
          
          return (
            <NavigationItem 
              key={item.name}
              item={item}
              isActive={isActive}
              isMobile={isMobile}
              isCollapsed={isCollapsed}
              onItemClick={onItemClick}
            />
          )
        })}
      </div>
    </div>
  )
}

export function ResponsiveNavigation({ 
  proxyType, 
  supportedFeatures, 
  className 
}: ResponsiveNavigationProps) {
  const { isMobile, isTablet } = useBreakpoints()
  const [isCollapsed, setIsCollapsed] = useState(false)
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  
  const navigation = getNavigationForProxy(proxyType, supportedFeatures)
  
  // Auto-collapse on tablet, expand on desktop
  useEffect(() => {
    if (isTablet) {
      setIsCollapsed(true)
    } else if (!isMobile) {
      setIsCollapsed(false)
    }
  }, [isMobile, isTablet])
  
  const handleMobileMenuClose = () => {
    setIsMobileMenuOpen(false)
  }
  
  // Desktop/Tablet Sidebar
  const SidebarContent = ({ isMobileSheet = false }) => (
    <div
      className={cn(
        "flex flex-col h-full bg-card text-card-foreground border-r transition-all duration-300",
        isMobileSheet ? "w-full" : (isCollapsed ? "w-16" : "w-64"),
        !isMobileSheet && isMobile && "hidden"
      )}
    >
      {/* Header */}
      <div className={cn(
        "flex items-center p-4 border-b", 
        isCollapsed && !isMobileSheet ? "justify-center" : "justify-between"
      )}>
        {(!isCollapsed || isMobileSheet) && (
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
        
        {!isMobileSheet && (
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setIsCollapsed(!isCollapsed)}
            className={cn("h-8 w-8", isCollapsed && "w-full")}
          >
            {isCollapsed ? (
              <ChevronRight className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </Button>
        )}
        
        {isMobileSheet && (
          <Button
            variant="ghost"
            size="icon"
            onClick={handleMobileMenuClose}
            className="h-8 w-8"
          >
            <X className="h-4 w-4" />
          </Button>
        )}
      </div>

      {/* Navigation */}
      <ScrollArea className="flex-1 px-2 py-4">
        <div className="space-y-6">
          {navigation.map((group) => (
            <NavigationGroup
              key={group.title}
              group={group}
              isCollapsed={isCollapsed && !isMobileSheet}
              isMobile={isMobileSheet}
              onItemClick={isMobileSheet ? handleMobileMenuClose : undefined}
            />
          ))}
        </div>
      </ScrollArea>
    </div>
  )
  
  if (isMobile) {
    return (
      <Sheet open={isMobileMenuOpen} onOpenChange={setIsMobileMenuOpen}>
        <SheetTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="h-9 w-9"
          >
            <Menu className="h-5 w-5" />
          </Button>
        </SheetTrigger>
        <SheetContent side="left" className="p-0 w-80">
          <SidebarContent isMobileSheet={true} />
        </SheetContent>
      </Sheet>
    )
  }
  
  return (
    <div className={cn("relative", className)}>
      <SidebarContent />
    </div>
  )
}

export default ResponsiveNavigation