/**
 * Example component demonstrating the complete proxy setup and configuration interface
 * This shows the full workflow from initial setup through migration and settings management
 */

import { useState } from 'react'
import { BrowserRouter } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Separator } from '@/components/ui/separator'
import { ProxySetupWizard } from '@/components/setup/ProxySetupWizard.tsx'
import { ProxyConfigurationForm as ProxySetupConfig } from '@/components/setup/ProxyConfigurationForm.tsx'
import { MigrationWizard } from '@/components/migration/MigrationWizard.tsx'
import { ProxySettingsManager } from '@/components/settings/ProxySettingsManager.tsx'
import { ProxyType, Feature } from '@/lib/proxy-types'
import { Settings, Zap, Database, RefreshCw } from 'lucide-react'

export function ProxySetupExample() {
  const [currentProxy, setCurrentProxy] = useState<ProxyType>('traefik')
  const [setupComplete, setSetupComplete] = useState(false)
  const [showMigration, setShowMigration] = useState(false)

  // Mock current settings
  const mockSettings = {
    proxyType: currentProxy,
    containerName: currentProxy,
    configPaths: {
      dynamic: `/etc/${currentProxy}/dynamic.yml`,
      static: `/etc/${currentProxy}/static.yml`,
      logs: `/var/log/${currentProxy}`
    },
    customSettings: {
      'log-level': 'INFO',
      'api-dashboard': 'true'
    },
    enabledFeatures: ['health', 'logs', 'bouncer'] as Feature[],
    healthCheckEnabled: true,
    metricsEnabled: currentProxy === 'traefik',
    autoRestart: true
  }

  // Mock legacy configuration for migration demo
  const mockLegacyConfig = {
    type: 'traefik' as const,
    version: '1.0.0',
    configFiles: [
      '/etc/traefik/traefik.yml',
      '/etc/traefik/dynamic_config.yml'
    ],
    hasData: true
  }

  const handleSetupComplete = (config: ProxySetupConfig) => {
    console.log('Setup completed with config:', config)
    setCurrentProxy(config.proxyType)
    setSetupComplete(true)
  }

  const handleMigrationComplete = (newProxyType: ProxyType) => {
    console.log('Migration completed to:', newProxyType)
    setCurrentProxy(newProxyType)
    setShowMigration(false)
    setSetupComplete(true)
  }

  const handleSettingsUpdate = (settings: any) => {
    console.log('Settings updated:', settings)
  }

  const resetDemo = () => {
    setSetupComplete(false)
    setShowMigration(false)
    setCurrentProxy('traefik')
  }

  return (
    <BrowserRouter>
      <div className="min-h-screen bg-background p-6">
        <div className="max-w-6xl mx-auto space-y-6">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold">Proxy Setup & Configuration Demo</h1>
              <p className="text-muted-foreground">
                Complete workflow for proxy setup, migration, and settings management
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="flex items-center gap-1">
                <Settings className="h-3 w-3" />
                {currentProxy.charAt(0).toUpperCase() + currentProxy.slice(1)}
              </Badge>
              <Button variant="outline" onClick={resetDemo} className="flex items-center gap-2">
                <RefreshCw className="h-4 w-4" />
                Reset Demo
              </Button>
            </div>
          </div>

          <Tabs defaultValue="setup" className="space-y-6">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="setup">Initial Setup</TabsTrigger>
              <TabsTrigger value="migration">Migration</TabsTrigger>
              <TabsTrigger value="settings">Settings Management</TabsTrigger>
              <TabsTrigger value="overview">Overview</TabsTrigger>
            </TabsList>

            {/* Initial Setup */}
            <TabsContent value="setup" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Zap className="h-5 w-5" />
                    Proxy Setup Wizard
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ProxySetupWizard
                    onComplete={handleSetupComplete}
                    initialProxy={currentProxy}
                  />
                </CardContent>
              </Card>
            </TabsContent>

            {/* Migration */}
            <TabsContent value="migration" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Database className="h-5 w-5" />
                    Migration Wizard
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex gap-2">
                      <Button 
                        onClick={() => setShowMigration(true)}
                        disabled={showMigration}
                      >
                        Simulate Legacy Detection
                      </Button>
                      <Button 
                        variant="outline"
                        onClick={() => setShowMigration(false)}
                      >
                        Reset Migration
                      </Button>
                    </div>
                    
                    <Separator />
                    
                    <MigrationWizard
                      detectedLegacyConfig={showMigration ? mockLegacyConfig : undefined}
                      onMigrationComplete={handleMigrationComplete}
                      onSkipMigration={() => setShowMigration(false)}
                    />
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Settings Management */}
            <TabsContent value="settings" className="space-y-6">
              <ProxySettingsManager
                currentSettings={mockSettings}
                onSettingsUpdate={handleSettingsUpdate}
              />
            </TabsContent>

            {/* Overview */}
            <TabsContent value="overview" className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Setup Wizard</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <p className="text-sm text-muted-foreground">
                      Complete 3-step wizard for initial proxy configuration
                    </p>
                    <ul className="text-xs text-muted-foreground space-y-1">
                      <li>• Proxy type selection with feature preview</li>
                      <li>• Dynamic configuration form</li>
                      <li>• Review and confirmation</li>
                    </ul>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Migration System</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <p className="text-sm text-muted-foreground">
                      Automatic migration from legacy Traefik configurations
                    </p>
                    <ul className="text-xs text-muted-foreground space-y-1">
                      <li>• Legacy configuration detection</li>
                      <li>• Step-by-step migration process</li>
                      <li>• Onboarding tour for new features</li>
                    </ul>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Settings Management</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <p className="text-sm text-muted-foreground">
                      Comprehensive proxy settings and health monitoring
                    </p>
                    <ul className="text-xs text-muted-foreground space-y-1">
                      <li>• Tabbed interface for different settings</li>
                      <li>• Real-time health monitoring</li>
                      <li>• Feature toggle management</li>
                    </ul>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Key Features</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div className="space-y-2">
                      <Badge variant="secondary" className="text-xs">
                        Proxy Type Immutability
                      </Badge>
                      <Badge variant="secondary" className="text-xs">
                        Backward Compatibility
                      </Badge>
                      <Badge variant="secondary" className="text-xs">
                        Feature Detection
                      </Badge>
                      <Badge variant="secondary" className="text-xs">
                        Health Monitoring
                      </Badge>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Supported Proxies</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span>Traefik</span>
                        <Badge variant="default" className="text-xs">Full Support</Badge>
                      </div>
                      <div className="flex items-center justify-between text-xs">
                        <span>Nginx PM</span>
                        <Badge variant="secondary" className="text-xs">Partial</Badge>
                      </div>
                      <div className="flex items-center justify-between text-xs">
                        <span>Caddy</span>
                        <Badge variant="secondary" className="text-xs">Basic</Badge>
                      </div>
                      <div className="flex items-center justify-between text-xs">
                        <span>HAProxy</span>
                        <Badge variant="secondary" className="text-xs">Basic</Badge>
                      </div>
                      <div className="flex items-center justify-between text-xs">
                        <span>Zoraxy</span>
                        <Badge variant="outline" className="text-xs">Experimental</Badge>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Demo Status</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span>Setup Complete:</span>
                        <Badge variant={setupComplete ? "default" : "outline"}>
                          {setupComplete ? "Yes" : "No"}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between text-sm">
                        <span>Current Proxy:</span>
                        <Badge variant="secondary">
                          {currentProxy.charAt(0).toUpperCase() + currentProxy.slice(1)}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between text-sm">
                        <span>Migration Active:</span>
                        <Badge variant={showMigration ? "default" : "outline"}>
                          {showMigration ? "Yes" : "No"}
                        </Badge>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </BrowserRouter>
  )
}