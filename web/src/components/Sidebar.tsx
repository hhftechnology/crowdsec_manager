import { Link, useLocation } from 'react-router-dom'
import { cn } from '@/lib/utils'
import {
  LayoutDashboard,
  Shield,
  Network,
  ListFilter,
  ScanFace,
  FileText,
  Database,
  RefreshCw,
  Clock,
  Settings,
  Activity,
  Github,
  MessageCircle,
  Sliders,
} from 'lucide-react'
import { Separator } from './ui/separator'

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Health & Diagnostics', href: '/health', icon: Activity },
  { name: 'IP Management', href: '/ip-management', icon: Network },
  { name: 'Whitelist', href: '/whitelist', icon: ListFilter },
  { name: 'Scenarios', href: '/scenarios', icon: Shield },
  { name: 'Captcha', href: '/captcha', icon: ScanFace },
  { name: 'Logs & Monitoring', href: '/logs', icon: FileText },
  { name: 'Backups', href: '/backup', icon: Database },
  { name: 'Stack Update', href: '/update', icon: RefreshCw },
  { name: 'Cron Jobs', href: '/cron', icon: Clock },
  { name: 'Services', href: '/services', icon: Settings },
  { name: 'Configuration', href: '/configuration', icon: Sliders },
]

export default function Sidebar() {
  const location = useLocation()

  return (
    <div className="w-64 bg-card border-r border-border flex flex-col">
      <div className="p-6">
        <h1 className="text-2xl font-bold text-primary">CrowdSec Manager</h1>
        <p className="text-sm text-muted-foreground mt-1">Security Management</p>
      </div>
      <Separator />
      <nav className="flex-1 overflow-y-auto p-4">
        <ul className="space-y-1">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href
            const Icon = item.icon
            return (
              <li key={item.name}>
                <Link
                  to={item.href}
                  className={cn(
                    'flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-primary text-primary-foreground'
                      : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                  )}
                >
                  <Icon className="h-5 w-5" />
                  {item.name}
                </Link>
              </li>
            )
          })}
        </ul>
      </nav>
      <Separator />
      <div className="p-4 space-y-2">
        <p className="text-xs text-muted-foreground font-semibold mb-2">Developer Links</p>
        <a
          href="https://github.com/hhftechnology/crowdsec-manager"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 px-3 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-accent rounded-md transition-colors"
        >
          <Github className="h-4 w-4" />
          <span>GitHub</span>
        </a>
        <a
          href="https://discord.gg/xCtMFeUKf9"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 px-3 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-accent rounded-md transition-colors"
        >
          <MessageCircle className="h-4 w-4" />
          <span>Discord</span>
        </a>
      </div>
    </div>
  )
}
