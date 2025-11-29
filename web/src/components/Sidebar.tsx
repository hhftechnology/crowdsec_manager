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
  ChevronDown,
  Moon,
  MessageSquare,
  ChevronsUpDown,
  LogOut,
  User,
  CreditCard,
  Settings2,
} from 'lucide-react'
import { Button } from './ui/button'
import { ScrollArea } from './ui/scroll-area'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"

const navigation = [
  {
    title: "Getting started",
    items: [
      { name: 'Dashboard', href: '/', icon: LayoutDashboard },
      { name: 'Engines', href: '/bouncers', icon: Shield }, // Mapped Bouncers to Engines
      { name: 'Health', href: '/health', icon: HeartPulse },
    ]
  },
  {
    title: "Activity",
    items: [
      { name: 'Alerts', href: '/alerts', icon: AlertTriangle },
      { name: 'Decisions', href: '/decisions', icon: Target },
      { name: 'Remediation Metrics', href: '/crowdsec-health', icon: Activity }, // Mapped CrowdSec Health
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

export default function Sidebar() {
  const location = useLocation()

  return (
    <div className="flex flex-col h-full bg-[#0B1120] text-slate-300 border-r border-slate-800 w-64 flex-shrink-0">
      {/* Top Header - Security Stack */}
      <div className="p-4 border-b border-slate-800">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="w-full justify-between px-2 hover:bg-slate-800 hover:text-white">
              <div className="flex items-center gap-2">
                <div className="bg-blue-600 p-1 rounded">
                  <Shield className="h-4 w-4 text-white" />
                </div>
                <span className="font-semibold">Security Stack</span>
              </div>
              <ChevronDown className="h-4 w-4 opacity-50" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-56 bg-[#0B1120] border-slate-800 text-slate-300">
            <DropdownMenuLabel>My Stacks</DropdownMenuLabel>
            <DropdownMenuSeparator className="bg-slate-800" />
            <DropdownMenuItem className="hover:bg-slate-800 focus:bg-slate-800">
              <Shield className="mr-2 h-4 w-4" />
              <span>Production</span>
            </DropdownMenuItem>
            <DropdownMenuItem className="hover:bg-slate-800 focus:bg-slate-800">
              <Shield className="mr-2 h-4 w-4" />
              <span>Staging</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* Organization Switcher */}
      <div className="p-4">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" className="w-full justify-between px-3 py-6 bg-[#161b2c] border-slate-800 hover:bg-slate-800 hover:text-white text-left h-auto">
              <div className="flex items-center gap-3">
                <Avatar className="h-8 w-8 rounded-md border border-slate-700">
                  <AvatarImage src="https://github.com/shadcn.png" alt="@shadcn" />
                  <AvatarFallback className="rounded-md bg-slate-800">CN</AvatarFallback>
                </Avatar>
                <div className="flex flex-col text-left">
                  <span className="text-sm font-semibold text-white">HHF Technologies</span>
                  <span className="text-xs text-slate-500">Personal account</span>
                </div>
              </div>
              <ChevronsUpDown className="h-4 w-4 opacity-50" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-56 bg-[#0B1120] border-slate-800 text-slate-300">
            <DropdownMenuLabel>My Account</DropdownMenuLabel>
            <DropdownMenuSeparator className="bg-slate-800" />
            <DropdownMenuGroup>
              <DropdownMenuItem className="hover:bg-slate-800 focus:bg-slate-800">
                <User className="mr-2 h-4 w-4" />
                <span>Profile</span>
                <DropdownMenuShortcut>⇧⌘P</DropdownMenuShortcut>
              </DropdownMenuItem>
              <DropdownMenuItem className="hover:bg-slate-800 focus:bg-slate-800">
                <CreditCard className="mr-2 h-4 w-4" />
                <span>Billing</span>
                <DropdownMenuShortcut>⌘B</DropdownMenuShortcut>
              </DropdownMenuItem>
              <DropdownMenuItem className="hover:bg-slate-800 focus:bg-slate-800">
                <Settings2 className="mr-2 h-4 w-4" />
                <span>Settings</span>
                <DropdownMenuShortcut>⌘S</DropdownMenuShortcut>
              </DropdownMenuItem>
            </DropdownMenuGroup>
            <DropdownMenuSeparator className="bg-slate-800" />
            <DropdownMenuItem className="hover:bg-slate-800 focus:bg-slate-800">
              <LogOut className="mr-2 h-4 w-4" />
              <span>Log out</span>
              <DropdownMenuShortcut>⇧⌘Q</DropdownMenuShortcut>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        <Button className="w-full mt-4 bg-amber-500 hover:bg-amber-600 text-black font-semibold">
          <span className="mr-2">🏆</span> Try the new Enterprise offer!
        </Button>
      </div>

      {/* Navigation */}
      <ScrollArea className="flex-1 px-4">
        <div className="space-y-6 pb-6">
          {navigation.map((group) => (
            <div key={group.title}>
              <h4 className="mb-2 px-2 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                {group.title}
              </h4>
              <div className="space-y-1">
                {group.items.map((item) => {
                  const isActive = location.pathname === item.href
                  const Icon = item.icon
                  return (
                    <Link
                      key={item.name}
                      to={item.href}
                      className={cn(
                        "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
                        isActive
                          ? "bg-slate-800 text-white"
                          : "text-slate-400 hover:bg-slate-800/50 hover:text-white"
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

      {/* Footer */}
      <div className="p-4 border-t border-slate-800 space-y-2">
        <div className="flex items-center justify-between text-slate-400 hover:text-white cursor-pointer px-2 py-1">
          <span className="text-sm">Back to the default design</span>
        </div>
        <div className="flex items-center justify-between px-2 py-1">
          <Button variant="ghost" size="sm" className="text-slate-400 hover:text-white p-0 h-auto font-normal">
            <MessageSquare className="h-4 w-4 mr-2" />
            Feedback
          </Button>
          <Button variant="ghost" size="icon" className="h-8 w-8 text-slate-400 hover:text-white">
            <Moon className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  )
}
