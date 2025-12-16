import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
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
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ProxyType, Feature } from '@/lib/proxy-types'
import { getNavigationForProxy, getQuickActionsForProxy } from '@/components/navigation/ProxyAwareNavigation'
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
  Keyboard
} from 'lucide-react'

interface GlobalSearchProps {
  proxyType: ProxyType
  supportedFeatures: Feature[]
  className?: string
}

interface SearchResult {
  id: string
  title: string
  description: string
  href: string
  icon: any
  category: string
  available: boolean
  keywords: string[]
}

export function GlobalSearch({ proxyType, supportedFeatures, className }: GlobalSearchProps) {
  const [open, setOpen] = useState(false)
  const navigate = useNavigate()

  // Generate search results based on proxy type and features
  const generateSearchResults = (): SearchResult[] => {
    const navigation = getNavigationForProxy(proxyType, supportedFeatures)
    const quickActions = getQuickActionsForProxy(proxyType, supportedFeatures)
    
    const results: SearchResult[] = []

    // Add navigation items
    navigation.forEach(group => {
      group.items.forEach(item => {
        results.push({
          id: `nav-${item.href}`,
          title: item.name,
          description: `Navigate to ${item.name}`,
          href: item.href,
          icon: item.icon,
          category: group.title,
          available: item.available,
          keywords: [item.name.toLowerCase(), group.title.toLowerCase()]
        })
      })
    })

    // Add quick actions
    quickActions.forEach(action => {
      results.push({
        id: `action-${action.href}`,
        title: action.name,
        description: `Quick action: ${action.name}`,
        href: action.href,
        icon: action.icon,
        category: 'Quick Actions',
        available: action.available,
        keywords: [action.name.toLowerCase(), 'quick', 'action']
      })
    })

    // Add proxy-specific actions
    const proxyActions: SearchResult[] = [
      {
        id: 'check-proxy-health',
        title: 'Check Proxy Health',
        description: `Check ${proxyType} container health`,
        href: '/proxy-health',
        icon: HeartPulse,
        category: 'Proxy Operations',
        available: true,
        keywords: ['health', 'check', 'proxy', proxyType]
      }
    ]

    if (supportedFeatures.includes('whitelist')) {
      proxyActions.push({
        id: 'add-ip-whitelist',
        title: 'Add IP to Whitelist',
        description: 'Add an IP address to the proxy whitelist',
        href: '/proxy-whitelist',
        icon: ListFilter,
        category: 'Proxy Operations',
        available: true,
        keywords: ['whitelist', 'ip', 'add', 'allow']
      })
    }

    if (supportedFeatures.includes('captcha')) {
      proxyActions.push({
        id: 'configure-captcha',
        title: 'Configure Captcha',
        description: 'Set up captcha protection',
        href: '/captcha',
        icon: ScanFace,
        category: 'Proxy Operations',
        available: true,
        keywords: ['captcha', 'configure', 'protection', 'security']
      })
    }

    if (supportedFeatures.includes('logs')) {
      proxyActions.push({
        id: 'view-proxy-logs',
        title: 'View Proxy Logs',
        description: `View ${proxyType} access logs`,
        href: '/proxy-logs',
        icon: FileText,
        category: 'Proxy Operations',
        available: true,
        keywords: ['logs', 'view', 'access', proxyType]
      })
    }

    // Add CrowdSec actions
    const crowdsecActions: SearchResult[] = [
      {
        id: 'view-decisions',
        title: 'View Security Decisions',
        description: 'View active CrowdSec decisions',
        href: '/decisions',
        icon: Target,
        category: 'CrowdSec Operations',
        available: true,
        keywords: ['decisions', 'security', 'crowdsec', 'blocked']
      },
      {
        id: 'view-alerts',
        title: 'View Security Alerts',
        description: 'View CrowdSec security alerts',
        href: '/alerts',
        icon: AlertTriangle,
        category: 'CrowdSec Operations',
        available: true,
        keywords: ['alerts', 'security', 'crowdsec', 'threats']
      },
      {
        id: 'manage-bouncers',
        title: 'Manage Bouncers',
        description: 'Manage CrowdSec bouncers',
        href: '/bouncers',
        icon: Shield,
        category: 'CrowdSec Operations',
        available: true,
        keywords: ['bouncers', 'manage', 'crowdsec', 'enforcement']
      }
    ]

    return [...results, ...proxyActions, ...crowdsecActions]
  }

  const searchResults = generateSearchResults()

  // Keyboard shortcut to open search
  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        setOpen((open) => !open)
      }
    }
    document.addEventListener('keydown', down)
    return () => document.removeEventListener('keydown', down)
  }, [])

  const handleSelect = (href: string) => {
    setOpen(false)
    navigate(href)
  }

  const groupedResults = searchResults.reduce((acc, result) => {
    if (!acc[result.category]) {
      acc[result.category] = []
    }
    acc[result.category].push(result)
    return acc
  }, {} as Record<string, SearchResult[]>)

  return (
    <>
      <Button
        variant="outline"
        className={`relative w-full justify-start text-sm text-muted-foreground sm:pr-12 md:w-40 lg:w-64 ${className}`}
        onClick={() => setOpen(true)}
      >
        <Search className="mr-2 h-4 w-4" />
        <span className="hidden lg:inline-flex">Search features, IPs, logs...</span>
        <span className="inline-flex lg:hidden">Search...</span>
        <kbd className="pointer-events-none absolute right-1.5 top-1.5 hidden h-5 select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium opacity-100 sm:flex">
          <span className="text-xs">⌘</span>K
        </kbd>
      </Button>

      <CommandDialog open={open} onOpenChange={setOpen}>
        <CommandInput placeholder="Search features, navigate, or perform actions..." />
        <CommandList>
          <CommandEmpty>No results found.</CommandEmpty>
          
          {Object.entries(groupedResults).map(([category, results]) => (
            <div key={category}>
              <CommandGroup heading={category}>
                {results
                  .filter(result => result.available)
                  .map((result) => {
                    const Icon = result.icon
                    return (
                      <CommandItem
                        key={result.id}
                        value={`${result.title} ${result.keywords.join(' ')}`}
                        onSelect={() => handleSelect(result.href)}
                      >
                        <Icon className="mr-2 h-4 w-4" />
                        <div className="flex flex-col">
                          <span>{result.title}</span>
                          <span className="text-xs text-muted-foreground">
                            {result.description}
                          </span>
                        </div>
                      </CommandItem>
                    )
                  })}
              </CommandGroup>
              {category !== Object.keys(groupedResults)[Object.keys(groupedResults).length - 1] && (
                <CommandSeparator />
              )}
            </div>
          ))}

          <CommandSeparator />
          <CommandGroup heading="Proxy Context">
            <CommandItem disabled>
              <Network className="mr-2 h-4 w-4" />
              <div className="flex items-center gap-2">
                <span>Current Proxy:</span>
                <Badge variant="outline" className="text-xs">
                  {proxyType.charAt(0).toUpperCase() + proxyType.slice(1)}
                </Badge>
              </div>
            </CommandItem>
            <CommandItem disabled>
              <Shield className="mr-2 h-4 w-4" />
              <div className="flex items-center gap-2">
                <span>Available Features:</span>
                <Badge variant="secondary" className="text-xs">
                  {supportedFeatures.length}
                </Badge>
              </div>
            </CommandItem>
          </CommandGroup>
        </CommandList>
      </CommandDialog>
    </>
  )
}