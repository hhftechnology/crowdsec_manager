import { useState } from 'react'
import { ProxyType, Feature } from '@/lib/proxy-types'
import { AdaptiveWhitelistManager } from '@/components/whitelist'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { Network, Settings } from 'lucide-react'

// Example proxy configurations with their supported features
const PROXY_CONFIGS: Record<ProxyType, Feature[]> = {
  traefik: ['whitelist', 'captcha', 'logs', 'bouncer', 'health', 'appsec'],
  nginx: ['logs', 'bouncer', 'health'],
  caddy: ['bouncer', 'health'],
  haproxy: ['bouncer', 'health'],
  zoraxy: ['health'],
  standalone: ['health']
}

export function AdaptiveWhitelistExample() {
  const [selectedProxy, setSelectedProxy] = useState<ProxyType>('traefik')
  const supportedFeatures = PROXY_CONFIGS[selectedProxy]

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            Proxy Configuration Demo
          </CardTitle>
          <CardDescription>
            Select different proxy types to see how the whitelist interface adapts
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="proxy-select">Select Proxy Type</Label>
            <Select value={selectedProxy} onValueChange={(value: ProxyType) => setSelectedProxy(value)}>
              <SelectTrigger id="proxy-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="traefik">Traefik (Full Features)</SelectItem>
                <SelectItem value="nginx">Nginx Proxy Manager (Limited)</SelectItem>
                <SelectItem value="caddy">Caddy (Basic)</SelectItem>
                <SelectItem value="haproxy">HAProxy (Basic)</SelectItem>
                <SelectItem value="zoraxy">Zoraxy (Experimental)</SelectItem>
                <SelectItem value="standalone">Standalone (CrowdSec Only)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Separator />

          <div className="space-y-2">
            <Label>Supported Features</Label>
            <div className="flex flex-wrap gap-2">
              {supportedFeatures.map(feature => (
                <Badge key={feature} variant="secondary" className="capitalize">
                  {feature}
                </Badge>
              ))}
            </div>
          </div>

          <div className="p-4 bg-muted/50 rounded-lg">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Network className="h-4 w-4" />
              <span>
                Current proxy: <strong className="capitalize">{selectedProxy}</strong>
                {selectedProxy === 'zoraxy' && ' (Experimental)'}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>

      <AdaptiveWhitelistManager 
        proxyType={selectedProxy}
        supportedFeatures={supportedFeatures}
      />
    </div>
  )
}