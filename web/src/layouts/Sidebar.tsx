import { Link, useLocation } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { Shield } from 'lucide-react'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { Badge } from "@/components/ui/badge"
import { navigation } from '@/layouts/navigation'

interface SidebarProps {
  isCollapsed: boolean
  onNavigate?: () => void
}

export default function Sidebar({ isCollapsed, onNavigate }: SidebarProps) {
  const location = useLocation()

  return (
    <div
      className={cn(
        "flex flex-col h-full bg-sidebar text-sidebar-foreground border-r border-sidebar-border transition-all duration-300",
        isCollapsed ? "w-16" : "w-64"
      )}
    >
      {/* Header with Toggle */}
      <div className={cn("flex items-center h-16 px-4 shrink-0 border-b border-sidebar-border", isCollapsed ? "justify-center" : "justify-between")}>
        {!isCollapsed && (
          <div className="flex items-center gap-2 font-semibold text-lg">
            <Shield className="h-6 w-6 text-primary" />
            <div className="flex flex-col">
              <span>CrowdSec Manager</span>
              <Badge variant="secondary" className="text-[10px] px-1 py-0 h-5 mt-1 w-fit whitespace-nowrap">
              v{import.meta.env.VITE_APP_VERSION}
              </Badge>
              <Badge variant="secondary" className="text-[10px] px-1 py-0 h-5 mt-1 w-fit whitespace-nowrap">
              v-Independent
              </Badge>
            </div>
          </div>
        )}
        {isCollapsed && (
          <Shield className="h-6 w-6 text-primary" />
        )}
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
                              onClick={onNavigate}
                              className={cn(
                                "flex items-center justify-center p-2 rounded-md transition-colors",
                                isActive
                                  ? "border-l-[3px] border-primary text-primary font-medium"
                                  : "text-muted-foreground hover:bg-sidebar-accent/50 hover:text-sidebar-foreground"
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
                      onClick={onNavigate}
                      className={cn(
                        "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors overflow-hidden",
                        isActive
                          ? "border-l-[3px] border-primary text-primary font-medium"
                          : "text-muted-foreground hover:bg-sidebar-accent/50 hover:text-sidebar-foreground"
                      )}
                    >
                      <Icon className="h-4 w-4 shrink-0" />
                      <span className="truncate">{item.name}</span>
                    </Link>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      </ScrollArea>

      {/* Footer with Copyright */}
      <div className="px-3 py-2 shrink-0">
        <Separator className="mb-3 bg-sidebar-border" />
        <div className={cn("flex items-center", isCollapsed ? "justify-center" : "justify-between gap-2")}>
          {!isCollapsed && (
            <p className="text-[10px] text-muted-foreground text-left leading-tight shrink-0">
              &copy; {new Date().getFullYear()} Crowdsec Manager by {' '}
            <a
            href="https://forum.hhf.technology"
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground hover:text-foreground transition-colors"
          >
            HHF Technology
          </a>
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
