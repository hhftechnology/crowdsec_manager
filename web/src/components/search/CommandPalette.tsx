import { useEffect, useState } from 'react'
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command'
import { Badge } from '@/components/ui/badge'
import { ProxyType, Feature } from '@/lib/proxy-types'
import { useCommandPalette } from '@/hooks/useCommandPalette'
import {
  Search,
  Shield,
  Activity,
  ListFilter,
  ScanFace,
  FileText,
  Target,
  AlertTriangle,
  Network,
  Settings,
  Database,
  RefreshCw,
  Bell,
  HeartPulse,
  LayoutDashboard,
  ListChecks,
  Clock,
  Sliders
} from 'lucide-react'

interface CommandPaletteProps {
  proxyType: ProxyType
  supportedFeatures: Feature[]
}

interface Command {
  id: string
  label: string
  description?: string
  href: string
  icon: any
  category: string
  keywords: string[]
  available: boolean
}

export function CommandPalette({ proxyType, supportedFeatures }: CommandPaletteProps) {
  const { isOpen, query, setQuery, executeCommand, close } = useCommandPalette({
    proxyType,
    supportedFeatures
  })

  // Generate all available commands
  const generateCommands = (): Command[] => {
    const commands: Command[] = [
      // Overview
      {
        id: 'dashboard',
        label: 'Dashboard',
        description: 'Go to main dashboard',
        href: '/',
        icon: LayoutDashboard,
        category: 'Navigation',
        keywords: ['dashboard', 'home', 'overview'],
        available: true
      },
      {
        id: 'proxy-health',
        label: 'Proxy Health',
        description: `Check ${proxyType} health status`,
        href: '/proxy-health',
        icon: HeartPulse,
        category: 'Navigation',
        keywords: ['health', 'proxy', 'status', proxyType],
        available: true
      },
      {
        id: 'crowdsec-health',
        label: 'CrowdSec Health',
        description: 'Check CrowdSec engine status',
        href: '/crowdsec-health',
        icon: Activity,
        category: 'Navigation',
        keywords: ['health', 'crowdsec', 'engine'],
        available: true
      },

      // Security
      {
        id: 'decisions',
        label: 'Security Decisions',
        description: 'View active security decisions',
        href: '/decisions',
        icon: Target,
        category: 'Security',
        keywords: ['decisions', 'security', 'blocked', 'banned'],
        available: true
      },
      {
        id: 'alerts',
        label: 'Security Alerts',
        description: 'View security alerts and threats',
        href: '/alerts',
        icon: AlertTriangle,
        category: 'Security',
        keywords: ['alerts', 'threats', 'security', 'attacks'],
        available: true
      },
      {
        id: 'bouncers',
        label: 'Bouncers',
        description: 'Manage CrowdSec bouncers',
        href: '/bouncers',
        icon: Shield,
        category: 'Security',
        keywords: ['bouncers', 'enforcement', 'agents'],
        available: true
      },

      // System
      {
        id: 'proxy-settings',
        label: 'Proxy Settings',
        description: 'Configure proxy settings',
        href: '/proxy-settings',
        icon: Settings,
        category: 'System',
        keywords: ['settings', 'proxy', 'configuration'],
        available: true
      },
      {
        id: 'notifications',
        label: 'Notifications',
        description: 'Manage notification settings',
        href: '/notifications',
        icon: Bell,
        category: 'System',
        keywords: ['notifications', 'alerts', 'settings'],
        available: true
      },
      {
        id: 'backups',
        label: 'Backups',
        description: 'Manage system backups',
        href: '/backup',
        icon: Database,
        category: 'System',
        keywords: ['backup', 'restore', 'data'],
        available: true
      },
      {
        id: 'updates',
        label: 'Updates',
        description: 'Check for system updates',
        href: '/update',
        icon: RefreshCw,
        category: 'System',
        keywords: ['update', 'upgrade', 'version'],
        available: true
      }
    ]

    // Add proxy-specific commands
    if (supportedFeatures.includes('logs')) {
      commands.push({
        id: 'proxy-logs',
        label: 'Reverse Proxy Logs',
        description: `View ${proxyType} access logs`,
        href: '/proxy-logs',
        icon: FileText,
        category: 'Proxy Management',
        keywords: ['logs', 'access', 'proxy', proxyType],
        available: true
      })
    }

    if (supportedFeatures.includes('whitelist')) {
      commands.push({
        id: 'proxy-whitelist',
        label: 'Proxy Whitelist',
        description: 'Manage IP whitelist at proxy level',
        href: '/proxy-whitelist',
        icon: ListFilter,
        category: 'Proxy Management',
        keywords: ['whitelist', 'ip', 'allow', 'proxy'],
        available: true
      })
    }

    if (supportedFeatures.includes('captcha')) {
      commands.push({
        id: 'captcha',
        label: 'Captcha Protection',
        description: 'Configure captcha middleware',
        href: '/captcha',
        icon: ScanFace,
        category: 'Proxy Management',
        keywords: ['captcha', 'protection', 'security', 'middleware'],
        available: true
      })
    }

    // Add CrowdSec configuration commands
    commands.push(
      {
        id: 'scenarios',
        label: 'Scenarios',
        description: 'Manage CrowdSec scenarios',
        href: '/scenarios',
        icon: FileText,
        category: 'CrowdSec Configuration',
        keywords: ['scenarios', 'rules', 'detection'],
        available: true
      },
      {
        id: 'allowlists',
        label: 'Allowlists',
        description: 'Manage CrowdSec allowlists',
        href: '/allowlist',
        icon: ListChecks,
        category: 'CrowdSec Configuration',
        keywords: ['allowlist', 'whitelist', 'crowdsec'],
        available: true
      },
      {
        id: 'profiles',
        label: 'Profiles',
        description: 'Manage CrowdSec profiles',
        href: '/profiles',
        icon: FileText,
        category: 'CrowdSec Configuration',
        keywords: ['profiles', 'remediation', 'actions'],
        available: true
      }
    )

    return commands.filter(cmd => cmd.available)
  }

  const commands = generateCommands()

  // Filter commands based on query
  const filteredCommands = commands.filter(command => {
    if (!query) return true
    
    const searchText = query.toLowerCase()
    return (
      command.label.toLowerCase().includes(searchText) ||
      command.description?.toLowerCase().includes(searchText) ||
      command.keywords.some(keyword => keyword.includes(searchText))
    )
  })

  // Group commands by category
  const groupedCommands = filteredCommands.reduce((acc, command) => {
    if (!acc[command.category]) {
      acc[command.category] = []
    }
    acc[command.category].push(command)
    return acc
  }, {} as Record<string, Command[]>)

  return (
    <CommandDialog open={isOpen} onOpenChange={close}>
      <CommandInput 
        placeholder="Search features, navigate, or perform actions..." 
        value={query}
        onValueChange={setQuery}
      />
      <CommandList>
        <CommandEmpty>
          <div className="flex flex-col items-center gap-2 py-6">
            <Search className="h-8 w-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">No results found</p>
            <p className="text-xs text-muted-foreground">
              Try searching for features like "whitelist", "logs", or "health"
            </p>
          </div>
        </CommandEmpty>
        
        {Object.entries(groupedCommands).map(([category, categoryCommands], index) => (
          <div key={category}>
            <CommandGroup heading={category}>
              {categoryCommands.map((command) => {
                const Icon = command.icon
                return (
                  <CommandItem
                    key={command.id}
                    value={`${command.label} ${command.keywords.join(' ')}`}
                    onSelect={() => executeCommand(command.href)}
                    className="flex items-center gap-2 px-4 py-2"
                  >
                    <Icon className="h-4 w-4 text-muted-foreground" />
                    <div className="flex flex-col flex-1">
                      <span className="font-medium">{command.label}</span>
                      {command.description && (
                        <span className="text-xs text-muted-foreground">
                          {command.description}
                        </span>
                      )}
                    </div>
                  </CommandItem>
                )
              })}
            </CommandGroup>
            {index < Object.keys(groupedCommands).length - 1 && <CommandSeparator />}
          </div>
        ))}

        {Object.keys(groupedCommands).length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Proxy Context">
              <CommandItem disabled className="flex items-center gap-2 px-4 py-2">
                <Network className="h-4 w-4 text-muted-foreground" />
                <div className="flex items-center gap-2">
                  <span className="text-sm">Current Proxy:</span>
                  <Badge variant="outline" className="text-xs">
                    {proxyType.charAt(0).toUpperCase() + proxyType.slice(1)}
                  </Badge>
                </div>
              </CommandItem>
              <CommandItem disabled className="flex items-center gap-2 px-4 py-2">
                <Shield className="h-4 w-4 text-muted-foreground" />
                <div className="flex items-center gap-2">
                  <span className="text-sm">Available Features:</span>
                  <div className="flex gap-1">
                    {supportedFeatures.map(feature => (
                      <Badge key={feature} variant="secondary" className="text-xs">
                        {feature}
                      </Badge>
                    ))}
                  </div>
                </div>
              </CommandItem>
            </CommandGroup>
          </>
        )}
      </CommandList>
    </CommandDialog>
  )
}