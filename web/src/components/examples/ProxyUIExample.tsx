/**
 * Example component demonstrating the enhanced UI component library
 * for multi-proxy architecture. This shows how all components work together
 * to provide a consistent, proxy-aware user experience.
 */

import { useState } from 'react'
import { BrowserRouter } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { ProxyStatusIndicator } from '@/components/proxy/ProxyStatusIndicator.tsx'
import { AdaptiveFeaturePanel } from '@/components/proxy/AdaptiveFeaturePanel.tsx'
import { ProxyTypeCard } from '@/components/proxy/ProxyTypeCard.tsx'
import { FeatureCard } from '@/components/proxy/FeatureCard.tsx'
import { StatusDashboard } from '@/components/proxy/StatusDashboard.tsx'
import { EnhancedSidebar } from '@/components/navigation/EnhancedSidebar.tsx'
import { GlobalSearch } from '@/components/search/GlobalSearch.tsx'
import { CommandPalette } from '@/components/search/CommandPalette.tsx'
import { ProxyType, Feature, PROXY_TYPES } from '@/lib/proxy-types'
import { Shield, Network, Activity } from 'lucide-react'

export function ProxyUIExample() {
  const [selectedProxy, setSelectedProxy] = useState<ProxyType>('traefik')
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)

  // Mock data based on selected proxy
  const getSupportedFeatures = (proxyType: ProxyType): Feature[] => {
    const featureMap: Record<ProxyType, Feature[]> = {
      traefik: ['whitelist', 'captcha', 'logs', 'bouncer', 'health', 'appsec'],
      nginx: ['logs', 'bouncer', 'health'],
      caddy: ['bouncer', 'health'],
      haproxy: ['bouncer', 'health'],
      zoraxy: ['health'],
      standalone: ['health']
    }
    return featureMap[proxyType] || []
  }

  const supportedFeatures = getSupportedFeatures(selectedProxy)

  const mockProxyStatus = {
    type: selectedProxy,
    running: true,
    connected: true,
    containerName: selectedProxy,
    healthStatus: 'healthy' as const
  }

  const mockStatusData = {
    proxyStatus: { running: true, connected: true },
    crowdsecStatus: { running: true, enrolled: true },
    bouncerStatus: { connected: true, lastSeen: '2 minutes ago' },
    decisions: { count: 156, active: 23 }
  }

  return (
    <BrowserRouter>
      <div className="min-h-screen bg-background">
        <div className="flex h-screen">
          {/* Enhanced Sidebar */}
          <EnhancedSidebar
            proxyType={selectedProxy}
            supportedFeatures={supportedFeatures}
            isCollapsed={sidebarCollapsed}
            setIsCollapsed={setSidebarCollapsed}
          />

          {/* Main Content */}
          <div className="flex-1 flex flex-col overflow-hidden">
            {/* Header with Global Search */}
            <header className="h-16 border-b border-border bg-background px-6 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <h1 className="text-xl font-semibold">Multi-Proxy UI Demo</h1>
                <ProxyStatusIndicator proxyStatus={mockProxyStatus} />
              </div>
              
              <div className="flex items-center gap-4">
                <GlobalSearch 
                  proxyType={selectedProxy}
                  supportedFeatures={supportedFeatures}
                  className="w-64"
                />
                <Badge variant="outline">
                  Demo Mode
                </Badge>
              </div>
            </header>

            {/* Main Content Area */}
            <main className="flex-1 overflow-y-auto p-6 space-y-6">
              {/* Proxy Type Selection */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Network className="h-5 w-5" />
                    Proxy Type Selection
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                    {PROXY_TYPES.map((proxy) => (
                      <ProxyTypeCard
                        key={proxy.type}
                        proxy={proxy}
                        selected={selectedProxy === proxy.type}
                        onSelect={(type) => setSelectedProxy(type as ProxyType)}
                      />
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Status Dashboard */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Activity className="h-5 w-5" />
                    System Status
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <StatusDashboard
                    proxyType={selectedProxy}
                    {...mockStatusData}
                  />
                </CardContent>
              </Card>

              {/* Adaptive Feature Panel */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    Available Features
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <AdaptiveFeaturePanel
                    proxyType={selectedProxy}
                    supportedFeatures={supportedFeatures}
                  />
                </CardContent>
              </Card>

              {/* Individual Feature Cards Example */}
              <Card>
                <CardHeader>
                  <CardTitle>Feature Card Examples</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <FeatureCard
                      title="Whitelist Management"
                      description="Manage IP whitelists at the proxy level"
                      icon={Shield}
                      available={supportedFeatures.includes('whitelist')}
                      href="/proxy-whitelist"
                      proxyType={selectedProxy}
                    />
                    <FeatureCard
                      title="Log Analysis"
                      description="Parse and analyze proxy access logs"
                      icon={Activity}
                      available={supportedFeatures.includes('logs')}
                      href="/proxy-logs"
                      proxyType={selectedProxy}
                    />
                    <FeatureCard
                      title="Health Monitoring"
                      description="Monitor proxy and system health"
                      icon={Network}
                      available={supportedFeatures.includes('health')}
                      href="/health"
                      proxyType={selectedProxy}
                    />
                  </div>
                </CardContent>
              </Card>

              {/* Current Configuration Summary */}
              <Card>
                <CardHeader>
                  <CardTitle>Current Configuration</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">Selected Proxy:</span>
                    <Badge variant="default">
                      {selectedProxy.charAt(0).toUpperCase() + selectedProxy.slice(1)}
                    </Badge>
                  </div>
                  
                  <Separator />
                  
                  <div className="space-y-2">
                    <span className="text-sm font-medium">Supported Features:</span>
                    <div className="flex flex-wrap gap-2">
                      {supportedFeatures.map(feature => (
                        <Badge key={feature} variant="secondary" className="text-xs">
                          {feature}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  
                  <Separator />
                  
                  <div className="text-xs text-muted-foreground">
                    This demo shows how the UI adapts based on the selected proxy type and its supported features.
                    Try selecting different proxy types to see how the interface changes.
                  </div>
                </CardContent>
              </Card>
            </main>
          </div>
        </div>

        {/* Command Palette */}
        <CommandPalette
          proxyType={selectedProxy}
          supportedFeatures={supportedFeatures}
        />
      </div>
    </BrowserRouter>
  )
}