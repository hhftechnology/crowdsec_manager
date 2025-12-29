import { Link, useLocation } from 'react-router-dom'
import { cn } from '@/lib/utils'
import {
  LayoutDashboard,
  Shield,
  Network,
  ListFilter,
  ListChecks,
  ScanFace,
  FileText,
  Database,
  RefreshCw,
  Clock,
  Settings,
  Activity,
  Sliders,
  AlertTriangle,
  Target,
  Bell,
  HeartPulse,
  PanelLeftClose,
  PanelLeftOpen,
  Moon,
  Sun,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Badge } from '@/components/ui/badge'
import { useTheme } from '@/components/ThemeProvider'
import { useBreakpoints } from '@/hooks/useMediaQuery'
import { ProxyType, Feature } from '@/lib/proxy-types'
import { useFeatures, useProxyType } from '@/contexts/DeploymentContext'
import { FeatureAvailability } from '@/lib/deployment-types'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'

interface AppSidebarProps {
  isCollapsed?: boolean
  onCollapsedChange?: (collapsed: boolean) => void
  className?: string
  // Optional overrides
  proxyType?: ProxyType
  supportedFeatures?: Feature[]
}

interface NavigationItem {
  name: string
  href: string
  icon: React.ComponentType<{ className?: string }>
  badge?: string | number
  available?: boolean
  tooltip?: string
}

interface NavigationSection {
  title: string
  items: NavigationItem[]
}

const baseNavigation: NavigationSection[] = [
  {
    title: "Getting started",
    items: [
      { name: 'Dashboard', href: '/', icon: LayoutDashboard, available: true },
      { name: 'Engines', href: '/bouncers', icon: Shield, available: true },
      { name: 'Health', href: '/health', icon: HeartPulse, available: true },
    ]
  },
  {
    title: "Activity",
    items: [
      { name: 'Alerts', href: '/alerts', icon: AlertTriangle, available: true },
      { name: 'Decisions', href: '/decisions', icon: Target, available: true },
      { name: 'Remediation Metrics', href: '/crowdsec-health', icon: Activity, available: true },
    ]
  },
  {
    title: "Hub",
    items: [
      { name: 'Scenarios', href: '/scenarios', icon: FileText, available: true },
      { name: 'Captcha', href: '/captcha', icon: ScanFace, available: true },
    ]
  },
  {
    title: "Configuration",
    items: [
      { name: 'Service API', href: '/services', icon: Settings, available: true },
      { name: 'Notification settings', href: '/notifications', icon: Bell, available: true },
      { name: 'Allowlists', href: '/allowlist', icon: ListChecks, available: true },
      { name: 'Whitelists', href: '/whitelist', icon: ListFilter, available: true },
      { name: 'Profiles', href: '/profiles', icon: FileText, available: true },
      { name: 'IP Management', href: '/ip-management', icon: Network, available: true },
    ]
  },
  {
    title: "System",
    items: [
      { name: 'Backups', href: '/backup', icon: Database, available: true },
      { name: 'Cron Jobs', href: '/cron', icon: Clock, available: true },
      { name: 'Logs', href: '/logs', icon: FileText, available: true },
      { name: 'Updates', href: '/update', icon: RefreshCw, available: true },
      { name: 'Settings', href: '/configuration', icon: Sliders, available: true },
    ]
  }
]

// Feature availability mapping
const getFeatureAvailability = (features: FeatureAvailability): Record<string, boolean> => {
  const availability: Record<string, boolean> = {}
  
  // Map routes to features.
  // Routes not listed here are considered available (available: true in baseNavigation) 
  // unless explicitly mapped to a feature that is false.
  const routeMap: Record<string, keyof FeatureAvailability> = {
    '/captcha': 'captcha',
    '/whitelist': 'whitelistProxy',
    '/proxy-logs': 'logs', // Assuming standard log route
    '/logs': 'logs',
    '/backup': 'backup',
    '/cron': 'cronJobs',
    '/bouncers': 'bouncer',
    '/appsec': 'appsec'
  }

  Object.entries(routeMap).forEach(([path, featureKey]) => {
    availability[path] = features[featureKey]
  })

  return availability
}

/**
 * AppSidebar - Enhanced collapsible navigation sidebar component
 * Provides hierarchical navigation with responsive behavior, proxy-aware features,
 * and touch-friendly interactions following the shadcn-admin template architecture
 */
export function AppSidebar({ 
  isCollapsed = false, 
  onCollapsedChange,
  className,
  proxyType: propProxyType,         // Optional override
  supportedFeatures: propFeatures   // Optional override (legacy/testing)
}: AppSidebarProps) {
  const location = useLocation()
  const { theme, setTheme } = useTheme()
  const { isMobile, needsTouchOptimization } = useBreakpoints()

  // Get context values
  const ctxFeatures = useFeatures()
  const ctxProxyType = useProxyType()

  // Determine effective proxy type description
  const displayProxyType = propProxyType || ctxProxyType

  // Determine effective feature availability map
  // If propFeatures provided, use that (backward compat/testing)
  // Else use context features
  let routeAvailability: Record<string, boolean> = {}
  
  if (propFeatures) {
     const featureMap: Record<string, string> = {
        'captcha': '/captcha',
        'whitelist': '/whitelist',
        'logs': '/logs',
        'backup': '/backup',
        'cron': '/cron',
        'bouncer': '/bouncers',
        'appsec': '/appsec'
     }
     // Default all false if utilizing props
     // Actually the old logic was: if prop missing, {} -> true.
     // But here we want to respect props.
     // Let's rely on getFeatureAvailability if we use context.
     // If props, we map manually.
     propFeatures.forEach(f => {
        if (featureMap[f]) routeAvailability[featureMap[f]] = true
        // Also map aliases
        if (f === 'whitelist') routeAvailability['/allowlist'] = true // assumpted
     })
  } else {
     routeAvailability = getFeatureAvailability(ctxFeatures)
  }

  const toggleTheme = () => {
    setTheme(theme === "dark" ? "light" : "dark")
  }

  const handleToggleCollapsed = () => {
    onCollapsedChange?.(!isCollapsed)
  }

  // Handle keyboard navigation
  const handleKeyDown = (event: React.KeyboardEvent, href: string) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      window.location.href = href
    }
  }

  // Get navigation with feature availability
  const navigation = baseNavigation.map(section => ({
    ...section,
    items: section.items.map(item => {
      // If routeAvailability has an entry, use it.
      // If not, fall back to item.available (default true)
      const isAvailable = routeAvailability[item.href] !== undefined 
          ? routeAvailability[item.href] 
          : item.available !== false
      
      return {
        ...item,
        available: isAvailable
      }
    })
  }))

  return (
    <nav
      className={cn(
        "flex flex-col bg-card text-card-foreground border-r transition-all duration-300",
        // Fixed height to enable scrolling
        "h-screen",
        isCollapsed ? "w-16" : "w-64",
        // Enhanced shadow for mobile overlay
        isMobile && "shadow-xl",
        className
      )}
      role="navigation"
      aria-label="Main navigation"
    >
      {/* Header with Logo and Toggle */}
      <div className={cn(
        "flex items-center border-b flex-shrink-0", 
        isCollapsed ? "justify-center p-3" : "justify-between p-4",
        // Touch-friendly padding on mobile
        needsTouchOptimization && !isCollapsed && "p-5"
      )}>
        {!isCollapsed && (
          <div className="flex items-center gap-2 font-semibold text-lg">
            <Shield className="h-6 w-6 text-primary" aria-hidden="true" />
            <div className="flex flex-col">
              <span>CrowdSec Manager</span>
              <div className="flex gap-1 mt-1">
                <Badge variant="secondary" className="text-[10px] px-1 py-0 h-5 w-fit whitespace-nowrap">
                  Beta-v0.0.6
                </Badge>
                {displayProxyType && (
                  <Badge variant="outline" className="text-[10px] px-1 py-0 h-5 w-fit whitespace-nowrap">
                    {displayProxyType.charAt(0).toUpperCase() + displayProxyType.slice(1)}
                  </Badge>
                )}
              </div>
            </div>
          </div>
        )}
        
        <Button
          variant="ghost"
          size="icon"
          onClick={handleToggleCollapsed}
          className={cn(
            "h-8 w-8", 
            isCollapsed && "w-full",
            // Touch-friendly sizing on mobile
            needsTouchOptimization && "h-10 w-10"
          )}
          aria-label={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {isCollapsed ? (
            <PanelLeftOpen className="h-4 w-4" />
          ) : (
            <PanelLeftClose className="h-4 w-4" />
          )}
        </Button>
      </div>

      {/* Navigation - Fixed scrolling container */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden px-2 py-4 scroll-smooth">
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
                  const Icon = item.icon
                  const isAvailable = item.available !== false
                  
                  if (isCollapsed) {
                    return (
                      <TooltipProvider key={item.name}>
                        <Tooltip delayDuration={0}>
                          <TooltipTrigger asChild>
                            <Link
                              to={item.href}
                              className={cn(
                                "flex items-center justify-center rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
                                // Touch-friendly sizing
                                needsTouchOptimization ? "p-3" : "p-2",
                                isActive
                                  ? "bg-primary text-primary-foreground"
                                  : isAvailable
                                  ? "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                                  : "text-muted-foreground/50 cursor-not-allowed opacity-50"
                              )}
                              aria-label={item.name}
                              onKeyDown={(e) => handleKeyDown(e, item.href)}
                              onClick={(e) => !isAvailable && e.preventDefault()}
                            >
                              <Icon className={cn(needsTouchOptimization ? "h-6 w-6" : "h-5 w-5")} />
                              {item.badge && (
                                <span className="sr-only">{item.badge} notifications</span>
                              )}
                            </Link>
                          </TooltipTrigger>
                          <TooltipContent side="right">
                            <div className="flex flex-col gap-1">
                              <div className="flex items-center gap-2">
                                {item.name}
                                {item.badge && (
                                  <Badge variant="secondary" className="text-xs">
                                    {item.badge}
                                  </Badge>
                                )}
                              </div>
                              {!isAvailable && item.tooltip && (
                                <span className="text-xs text-muted-foreground">{item.tooltip}</span>
                              )}
                              {!isAvailable && !item.tooltip && (
                                <span className="text-xs text-muted-foreground">
                                  Not available for {displayProxyType} proxy
                                </span>
                              )}
                            </div>
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    )
                  }

                  return (
                    <Link
                      key={item.name}
                      to={item.href}
                      className={cn(
                        "flex items-center gap-3 rounded-md text-sm transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
                        // Touch-friendly sizing
                        needsTouchOptimization ? "px-4 py-3" : "px-3 py-2",
                        isActive
                          ? "bg-primary text-primary-foreground"
                          : isAvailable
                          ? "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                          : "text-muted-foreground/50 cursor-not-allowed opacity-50"
                      )}
                      onKeyDown={(e) => handleKeyDown(e, item.href)}
                      onClick={(e) => !isAvailable && e.preventDefault()}
                    >
                      <Icon className={cn(needsTouchOptimization ? "h-5 w-5" : "h-4 w-4")} />
                      <span className="flex-1">{item.name}</span>
                      {item.badge && (
                        <Badge variant="secondary" className="text-xs">
                          {item.badge}
                        </Badge>
                      )}
                      {!isAvailable && (
                        <Badge variant="secondary" className="text-xs">
                          N/A
                        </Badge>
                      )}
                    </Link>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Footer with Theme Toggle */}
      <div className={cn(
        "border-t flex-shrink-0",
        needsTouchOptimization ? "p-5" : "p-4"
      )}>
        <Button
          variant="ghost"
          size={isCollapsed ? "icon" : "default"}
          onClick={toggleTheme}
          className={cn(
            "w-full justify-start transition-all focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
            isCollapsed && "justify-center",
            // Touch-friendly sizing on mobile
            needsTouchOptimization && "py-3 h-auto"
          )}
          aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
        >
          {theme === "dark" ? (
            <Sun className={cn(needsTouchOptimization ? "h-5 w-5" : "h-4 w-4")} />
          ) : (
            <Moon className={cn(needsTouchOptimization ? "h-5 w-5" : "h-4 w-4")} />
          )}
          {!isCollapsed && <span className="ml-2">Toggle Theme</span>}
        </Button>
      </div>
    </nav>
  )
}