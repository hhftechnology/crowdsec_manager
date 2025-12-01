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

export default function Sidebar({ isCollapsed, setIsCollapsed }: SidebarProps) {
  const location = useLocation()
  const { theme, setTheme } = useTheme()

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
      {/* Header with Toggle */}
      <div className={cn("flex items-center p-4 border-b", isCollapsed ? "justify-center" : "justify-between")}>
        {!isCollapsed && (
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
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setIsCollapsed(!isCollapsed)}
          className={cn("h-8 w-8", isCollapsed && "w-full")}
        >
          {isCollapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
        </Button>
      </div>

      {/* Navigation */}
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
                  const Icon = item.icon
                  
                  if (isCollapsed) {
                    return (
                      <TooltipProvider key={item.name}>
                        <Tooltip delayDuration={0}>
                          <TooltipTrigger asChild>
                            <Link
                              to={item.href}
                              className={cn(
                                "flex items-center justify-center p-2 rounded-md transition-colors",
                                isActive
                                  ? "bg-primary text-primary-foreground"
                                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                              )}
                            >
                              <Icon className="h-5 w-5" />
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
                        "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
                        isActive
                          ? "bg-primary text-primary-foreground"
                          : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                      )}
                    >
                      <Icon className="h-4 w-4" />
                      {item.name}
                    </Link>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      </ScrollArea>

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
