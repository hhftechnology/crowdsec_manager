import {
  LayoutDashboard,
  Shield,
  ListChecks,
  FileText,
  Settings,
  Activity,
  AlertTriangle,
  Target,
  HeartPulse,
  TerminalSquare,
  Package,
  BarChart3,
  ShieldAlert,
  ScanSearch,
  AppWindow,
  History,
} from 'lucide-react'

export const navigation = [
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
      { name: 'History', href: '/history', icon: History },
      { name: 'Remediation Metrics', href: '/crowdsec-health', icon: Activity },
      { name: 'Engine Metrics', href: '/metrics', icon: BarChart3 },
    ]
  },
  {
    title: "Hub",
    items: [
      { name: 'Home', href: '/hub', icon: Package },
      { name: 'Hub Browser', href: '/hub/browser', icon: Package },
      { name: 'Collections', href: '/hub/collections', icon: Package },
      { name: 'Attack scenarios', href: '/hub/scenarios', icon: ShieldAlert },
      { name: 'Log parsers', href: '/hub/parsers', icon: ScanSearch },
      { name: 'Postoverflows', href: '/hub/postoverflows', icon: ListChecks },
      { name: 'Remediation components', href: '/hub/remediations', icon: Shield },
      { name: 'AppSec configurations', href: '/hub/appsec-configs', icon: AppWindow },
      { name: 'AppSec rules', href: '/hub/appsec-rules', icon: ShieldAlert },
      { name: 'Scenarios', href: '/scenarios', icon: FileText },
    ]
  },
  {
    title: "Configuration",
    items: [
      { name: 'Service API', href: '/services', icon: Settings },
      { name: 'Allowlists', href: '/allowlist', icon: ListChecks },
    ]
  },
  {
    title: "System",
    items: [
      { name: 'Terminal', href: '/terminal', icon: TerminalSquare },
      { name: 'Logs', href: '/logs', icon: FileText },
    ]
  }
]
