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
  ChevronLeft,
  ChevronRight,
  Bell,
  HeartPulse,
} from 'lucide-react'
import { Separator } from './ui/separator'
import { Button } from './ui/button'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './ui/tooltip'

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Health & Diagnostics', href: '/health', icon: Activity },
  { name: 'CrowdSec Health', href: '/crowdsec-health', icon: HeartPulse },
  { name: 'IP Management', href: '/ip-management', icon: Network },
  { name: 'Whitelist', href: '/whitelist', icon: ListFilter },
  { name: 'Allowlist', href: '/allowlist', icon: ListChecks },
  { name: 'Scenarios', href: '/scenarios', icon: Shield },
  { name: 'Captcha', href: '/captcha', icon: ScanFace },
  { name: 'Decision Analysis', href: '/decisions', icon: Target },
  { name: 'Alert Analysis', href: '/alerts', icon: AlertTriangle },
  { name: 'Logs & Monitoring', href: '/logs', icon: FileText },
  { name: 'Backups', href: '/backup', icon: Database },
  { name: 'Stack Update', href: '/update', icon: RefreshCw },
  { name: 'Cron Jobs', href: '/cron', icon: Clock },
  { name: 'Services', href: '/services', icon: Settings },
  { name: 'Configuration', href: '/configuration', icon: Sliders },
  { name: 'Notifications', href: '/notifications', icon: Bell },
]

interface SidebarProps {
  isCollapsed: boolean
  onToggle: () => void
}

export default function Sidebar({ isCollapsed, onToggle }: SidebarProps) {
  const location = useLocation()

  return (
    <div
      className={cn(
        'bg-card border-r border-border flex flex-col transition-all duration-300',
        isCollapsed ? 'w-16' : 'w-64'
      )}
    >
      <div className={cn('p-6 flex items-center', isCollapsed ? 'justify-center' : 'justify-between')}>
        {!isCollapsed && (
          <div>
            <h2 className="text-2xl font-bold text-primary">Panel</h2>
            <p className="text-sm text-muted-foreground mt-1">Management</p>
          </div>
        )}
        <Button
          variant="ghost"
          size="icon"
          onClick={onToggle}
          className="h-8 w-8"
        >
          {isCollapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </Button>
      </div>
      <Separator />
      <nav className="flex-1 overflow-y-auto p-4">
        <TooltipProvider>
          <ul className="space-y-1">
            {navigation.map((item) => {
              const isActive = location.pathname === item.href
              const Icon = item.icon

              const linkContent = (
                <Link
                  to={item.href}
                  className={cn(
                    'flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-primary text-primary-foreground'
                      : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground',
                    isCollapsed && 'justify-center'
                  )}
                >
                  <Icon className="h-5 w-5 flex-shrink-0" />
                  {!isCollapsed && <span>{item.name}</span>}
                </Link>
              )

              return (
                <li key={item.name}>
                  {isCollapsed ? (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        {linkContent}
                      </TooltipTrigger>
                      <TooltipContent side="right">
                        <p>{item.name}</p>
                      </TooltipContent>
                    </Tooltip>
                  ) : (
                    linkContent
                  )}
                </li>
              )
            })}
          </ul>
        </TooltipProvider>
      </nav>
    </div>
  )
}
