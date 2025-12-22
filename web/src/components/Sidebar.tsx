/**
 * @deprecated This component is deprecated. Use AppSidebar from './layout/AppSidebar' instead.
 * This file will be removed in a future version.
 */

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
import { Button } from './ui/button'
import { ScrollArea } from './ui/scroll-area'
import { useTheme } from './ThemeProvider'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"

import { Badge } from "@/components/ui/badge"

interface SidebarProps {
  isCollapsed: boolean
  setIsCollapsed: (collapsed: boolean) => void
  isMobile?: boolean
  isMobileMenuOpen?: boolean
}

const navigation = [
  {
    title: "Getting started",
    items: [
      { name: 'Dashboard', href: '/', icon: LayoutDashboard },
      { name: 'Engines', href: '/bouncers', icon: Shield },
      { name: 'Health', href: '/health', icon: HeartPulse },
    ]
  },
  {
    title: "Activity",
    items: [
      { name: 'Alerts', href: '/alerts', icon: AlertTriangle },
      { name: 'Decisions', href: '/decisions', icon: Target },
      { name: 'Remediation Metrics', href: '/crowdsec-health', icon: Activity },
    ]
  },
  {
    title: "Hub",
    items: [
      { name: 'Scenarios', href: '/scenarios', icon: FileText },
      { name: 'Captcha', href: '/captcha', icon: ScanFace },
    ]
  },
  {
    title: "Configuration",
    items: [
      { name: 'Service API', href: '/services', icon: Settings },
      { name: 'Notification settings', href: '/notifications', icon: Bell },
      { name: 'Allowlists', href: '/allowlist', icon: ListChecks },
      { name: 'Whitelists', href: '/whitelist', icon: ListFilter },
      { name: 'Profiles', href: '/profiles', icon: FileText },
      { name: 'IP Management', href: '/ip-management', icon: Network },
    ]
  },
  {
    title: "System",
    items: [
      { name: 'Backups', href: '/backup', icon: Database },
      { name: 'Cron Jobs', href: '/cron', icon: Clock },
      { name: 'Logs', href: '/logs', icon: FileText },
      { name: 'Updates', href: '/update', icon: RefreshCw },
      { name: 'Settings', href: '/configuration', icon: Sliders },
    ]
  }
]

/**
 * @deprecated Use AppSidebar from './layout/AppSidebar' instead
 */
export default function Sidebar({ 
  isCollapsed, 
  setIsCollapsed, 
  isMobile = false, 
  // isMobileMenuOpen = false // Unused prop in deprecated component
}: SidebarProps) {
  const location = useLocation()
  const { theme, setTheme } = useTheme()

  const toggleTheme = () => {
    setTheme(theme === "dark" ? "light" : "dark")
  }

  // On mobile, always show full width when open
  const effectiveCollapsed = isMobile ? false : isCollapsed

  return (
    <nav
      id="navigation"
      role="navigation"
      aria-label="Main navigation"
      className={cn(
        "flex flex-col bg-card text-card-foreground border-r transition-all duration-300",
        // Fixed height to enable scrolling
        "h-screen",
        // Mobile: full width overlay
        isMobile ? "w-64 shadow-lg" : 
        // Desktop/Tablet: responsive width
        effectiveCollapsed ? "w-16" : "w-64"
      )}
    >
      {/* Header with Toggle */}
      <div className={cn(
        "flex items-center p-4 border-b flex-shrink-0", 
        effectiveCollapsed ? "justify-center" : "justify-between"
      )}>
        {!effectiveCollapsed && (
          <div className="flex items-center gap-2 font-semibold text-lg">
            <Shield className="h-6 w-6 text-primary" />
            <div className="flex flex-col">
              <span>CrowdSec Manager</span>
              <Badge variant="secondary" className="text-[10px] px-1 py-0 h-5 mt-1 w-fit whitespace-nowrap">
              Beta-v0.0.6
              </Badge>
            </div>
          </div>
        )}
        {/* Only show toggle button on desktop/tablet */}
        {!isMobile && (
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setIsCollapsed(!isCollapsed)}
            className={cn("h-8 w-8", effectiveCollapsed && "w-full")}
            aria-label={effectiveCollapsed ? "Expand navigation" : "Collapse navigation"}
          >
            {effectiveCollapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
          </Button>
        )}
      </div>

      {/* Navigation */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden px-2 py-4 scroll-smooth">
        <div className="space-y-6">
          {navigation.map((group) => (
            <div key={group.title}>
              {!effectiveCollapsed && (
                <h4 className="mb-2 px-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  {group.title}
                </h4>
              )}
              <div className="space-y-1">
                {group.items.map((item) => {
                  const isActive = location.pathname === item.href
                  const Icon = item.icon
                  
                  if (effectiveCollapsed) {
                    return (
                      <TooltipProvider key={item.name}>
                        <Tooltip delayDuration={0}>
                          <TooltipTrigger asChild>
                            <Link
                              to={item.href}
                              className={cn(
                                "flex items-center justify-center rounded-md transition-colors",
                                // Touch-friendly sizing on mobile
                                isMobile ? "p-3" : "p-2",
                                isActive
                                  ? "bg-primary text-primary-foreground"
                                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                              )}
                            >
                              <Icon className={cn(isMobile ? "h-6 w-6" : "h-5 w-5")} />
                            </Link>
                          </TooltipTrigger>
                          <TooltipContent side="right">
                            {item.name}
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
                        "flex items-center gap-3 rounded-md text-sm transition-colors",
                        // Touch-friendly sizing
                        isMobile ? "px-4 py-3" : "px-3 py-2",
                        isActive
                          ? "bg-primary text-primary-foreground"
                          : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                      )}
                    >
                      <Icon className={cn(isMobile ? "h-5 w-5" : "h-4 w-4")} />
                      {item.name}
                    </Link>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Footer with Theme Toggle */}
      <div className="p-4 border-t flex-shrink-0">
        <Button
          variant="ghost"
          size={effectiveCollapsed ? "icon" : "default"}
          onClick={toggleTheme}
          className={cn(
            "w-full justify-start transition-all",
            effectiveCollapsed && "justify-center",
            // Touch-friendly sizing on mobile
            isMobile && "py-3"
          )}
        >
          {theme === "dark" ? (
            <Sun className={cn(isMobile ? "h-5 w-5" : "h-4 w-4")} />
          ) : (
            <Moon className={cn(isMobile ? "h-5 w-5" : "h-4 w-4")} />
          )}
          {!effectiveCollapsed && <span className="ml-2">Toggle Theme</span>}
        </Button>
      </div>
    </nav>
  )
}
