import { ProxyType, Feature } from '@/lib/proxy-types'
import { NavigationGroup, NavigationItem } from '@/lib/proxy-types'
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
  HeartPulse
} from 'lucide-react'

/**
 * Generate navigation structure based on proxy type and supported features
 * This function creates a proxy-aware navigation menu that shows/hides items
 * based on what features are available for the selected proxy type.
 */
export function getNavigationForProxy(
  proxyType: ProxyType, 
  supportedFeatures: Feature[]
): NavigationGroup[] {
  return [
    {
      title: "Overview",
      items: [
        { 
          name: 'Dashboard', 
          href: '/', 
          icon: LayoutDashboard, 
          available: true 
        },
        { 
          name: 'Proxy Health', 
          href: '/proxy-health', 
          icon: HeartPulse, 
          available: true 
        },
        { 
          name: 'CrowdSec Health', 
          href: '/crowdsec-health', 
          icon: Activity, 
          available: true 
        },
      ]
    },
    {
      title: "Security",
      items: [
        { 
          name: 'Decisions', 
          href: '/decisions', 
          icon: Target, 
          available: true 
        },
        { 
          name: 'Alerts', 
          href: '/alerts', 
          icon: AlertTriangle, 
          available: true 
        },
        { 
          name: 'Bouncers', 
          href: '/bouncers', 
          icon: Shield, 
          available: true 
        },
      ]
    },
    {
      title: "Proxy Management",
      items: [
        { 
          name: 'Reverse Proxy Logs', 
          href: '/proxy-logs', 
          icon: FileText, 
          available: supportedFeatures.includes('logs'),
          tooltip: !supportedFeatures.includes('logs') 
            ? `Log parsing not supported for ${proxyType}` 
            : undefined
        },
        { 
          name: 'Proxy Whitelist', 
          href: '/proxy-whitelist', 
          icon: ListFilter, 
          available: supportedFeatures.includes('whitelist'),
          tooltip: !supportedFeatures.includes('whitelist') 
            ? `Whitelist management not supported for ${proxyType}` 
            : undefined
        },
        { 
          name: 'Captcha Protection', 
          href: '/captcha', 
          icon: ScanFace, 
          available: supportedFeatures.includes('captcha'),
          tooltip: !supportedFeatures.includes('captcha') 
            ? `Captcha not supported for ${proxyType}` 
            : undefined
        },
      ]
    },
    {
      title: "CrowdSec Configuration",
      items: [
        { 
          name: 'Scenarios', 
          href: '/scenarios', 
          icon: FileText, 
          available: true 
        },
        { 
          name: 'Allowlists', 
          href: '/allowlist', 
          icon: ListChecks, 
          available: true 
        },
        { 
          name: 'Profiles', 
          href: '/profiles', 
          icon: FileText, 
          available: true 
        },
      ]
    },
    {
      title: "System",
      items: [
        { 
          name: 'Proxy Settings', 
          href: '/proxy-settings', 
          icon: Settings, 
          available: true 
        },
        { 
          name: 'Notifications', 
          href: '/notifications', 
          icon: Bell, 
          available: true 
        },
        { 
          name: 'Backups', 
          href: '/backup', 
          icon: Database, 
          available: true 
        },
        { 
          name: 'Updates', 
          href: '/update', 
          icon: RefreshCw, 
          available: true 
        },
      ]
    }
  ]
}

/**
 * Get quick actions based on proxy type and supported features
 */
export function getQuickActionsForProxy(
  proxyType: ProxyType, 
  supportedFeatures: Feature[]
): NavigationItem[] {
  const actions: NavigationItem[] = [
    {
      name: 'Check Health',
      href: '/health',
      icon: HeartPulse,
      available: true
    }
  ]

  if (supportedFeatures.includes('whitelist')) {
    actions.push({
      name: 'Add to Whitelist',
      href: '/proxy-whitelist',
      icon: ListFilter,
      available: true
    })
  }

  if (supportedFeatures.includes('logs')) {
    actions.push({
      name: 'View Logs',
      href: '/proxy-logs',
      icon: FileText,
      available: true
    })
  }

  if (supportedFeatures.includes('captcha')) {
    actions.push({
      name: 'Configure Captcha',
      href: '/captcha',
      icon: ScanFace,
      available: true
    })
  }

  return actions
}