import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { ProxyType, Feature, PROXY_TYPES, FEATURE_DESCRIPTIONS } from '@/lib/proxy-types'
import {
  Settings,
  ListFilter,
  ScanFace,
  FileText,
  Shield,
  Activity,
  HeartPulse,
  Info,
  CheckCircle,
  XCircle
} from 'lucide-react'

interface FeatureTogglePanelProps {
  proxyType: ProxyType
  enabledFeatures: Feature[]
  onFeatureToggle: (feature: Feature, enabled: boolean) => void
  disabled?: boolean
  className?: string
}

const FEATURE_ICONS: Record<Feature, any> = {
  whitelist: ListFilter,
  captcha: ScanFace,
  logs: FileText,
  bouncer: Shield,
  health: HeartPulse,
  appsec: Activity
}

const FEATURE_TITLES: Record<Feature, string> = {
  whitelist: 'Whitelist Management',
  captcha: 'Captcha Protection',
  logs: 'Log Analysis',
  bouncer: 'Bouncer Integration',
  health: 'Health Monitoring',
  appsec: 'Application Security'
}

const FEATURE_DETAILS: Record<Feature, string> = {
  whitelist: 'Manage IP whitelists at the proxy level to allow trusted traffic',
  captcha: 'Configure captcha middleware to protect against automated attacks',
  logs: 'Parse and analyze proxy access logs for security insights',
  bouncer: 'Integrate with CrowdSec bouncer for real-time threat blocking',
  health: 'Monitor proxy container health and performance metrics',
  appsec: 'Enable application security features and WAF capabilities'
}

export function FeatureTogglePanel({ 
  proxyType, 
  enabledFeatures, 
  onFeatureToggle, 
  disabled = false,
  className 
}: FeatureTogglePanelProps) {
  const proxyInfo = PROXY_TYPES.find(p => p.type === proxyType)
  const supportedFeatures = proxyInfo?.features || []
  
  const allFeatures: Feature[] = ['whitelist', 'captcha', 'logs', 'bouncer', 'health', 'appsec']
  
  const isFeatureSupported = (feature: Feature) => {
    return supportedFeatures.includes(feature)
  }
  
  const isFeatureEnabled = (feature: Feature) => {
    return enabledFeatures.includes(feature)
  }
  
  const canToggleFeature = (feature: Feature) => {
    // Health feature is always required and cannot be disabled
    if (feature === 'health') return false
    return isFeatureSupported(feature) && !disabled
  }

  const getFeatureStatus = (feature: Feature) => {
    if (!isFeatureSupported(feature)) return 'unsupported'
    if (feature === 'health') return 'required'
    return isFeatureEnabled(feature) ? 'enabled' : 'disabled'
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'enabled':
        return <Badge className="bg-green-500">Enabled</Badge>
      case 'disabled':
        return <Badge variant="outline">Disabled</Badge>
      case 'required':
        return <Badge variant="default">Required</Badge>
      case 'unsupported':
        return <Badge variant="secondary">Not Supported</Badge>
      default:
        return <Badge variant="outline">Unknown</Badge>
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'enabled':
      case 'required':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'disabled':
        return <XCircle className="h-4 w-4 text-gray-500" />
      case 'unsupported':
        return <XCircle className="h-4 w-4 text-red-500" />
      default:
        return <XCircle className="h-4 w-4 text-gray-500" />
    }
  }

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Settings className="h-5 w-5" />
          Feature Management
        </CardTitle>
        <p className="text-sm text-muted-foreground">
          Configure which features are enabled for your {proxyInfo?.name} integration
        </p>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Feature List */}
        <div className="space-y-4">
          {allFeatures.map((feature, index) => {
            const Icon = FEATURE_ICONS[feature]
            const title = FEATURE_TITLES[feature]
            const description = FEATURE_DETAILS[feature]
            const status = getFeatureStatus(feature)
            const canToggle = canToggleFeature(feature)
            
            return (
              <div key={feature}>
                <div className="flex items-start gap-4">
                  <div className="flex items-center gap-3 flex-1">
                    <Icon className={`h-5 w-5 ${
                      status === 'enabled' || status === 'required' ? 'text-primary' : 
                      status === 'unsupported' ? 'text-red-500' : 'text-muted-foreground'
                    }`} />
                    
                    <div className="flex-1 space-y-1">
                      <div className="flex items-center gap-2">
                        <Label className="text-sm font-medium">{title}</Label>
                        {getStatusBadge(status)}
                      </div>
                      <p className="text-xs text-muted-foreground">
                        {description}
                      </p>
                      {status === 'unsupported' && (
                        <p className="text-xs text-red-600">
                          Not supported by {proxyInfo?.name}
                        </p>
                      )}
                      {status === 'required' && (
                        <p className="text-xs text-blue-600">
                          Required feature - cannot be disabled
                        </p>
                      )}
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-2">
                    {getStatusIcon(status)}
                    <Switch
                      checked={status === 'enabled' || status === 'required'}
                      onCheckedChange={(checked) => onFeatureToggle(feature, checked)}
                      disabled={!canToggle}
                    />
                  </div>
                </div>
                
                {index < allFeatures.length - 1 && <Separator className="mt-4" />}
              </div>
            )
          })}
        </div>

        {/* Feature Summary */}
        <Alert>
          <Info className="h-4 w-4" />
          <AlertDescription>
            <strong>Feature Summary:</strong> {enabledFeatures.length} of {supportedFeatures.length} supported features are enabled. 
            {supportedFeatures.length < allFeatures.length && (
              <span> {allFeatures.length - supportedFeatures.length} features are not supported by {proxyInfo?.name}.</span>
            )}
          </AlertDescription>
        </Alert>

        {/* Proxy-specific Notes */}
        {proxyType === 'traefik' && (
          <Alert>
            <Shield className="h-4 w-4" />
            <AlertDescription>
              <strong>Traefik Features:</strong> All features are supported including advanced 
              whitelist management, captcha middleware, and application security.
            </AlertDescription>
          </Alert>
        )}

        {proxyType === 'nginx' && (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              <strong>Nginx Proxy Manager:</strong> Log analysis and bouncer integration are supported. 
              Whitelist and captcha management should be configured through NPM interface.
            </AlertDescription>
          </Alert>
        )}

        {(proxyType === 'caddy' || proxyType === 'haproxy') && (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              <strong>{proxyInfo?.name} Features:</strong> Basic bouncer integration and health monitoring 
              are supported. Advanced features like whitelist and captcha are not available.
            </AlertDescription>
          </Alert>
        )}

        {proxyType === 'zoraxy' && (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              <strong>Zoraxy (Experimental):</strong> Only basic health monitoring is currently supported. 
              This proxy type is experimental and additional features may be added in future releases.
            </AlertDescription>
          </Alert>
        )}

        {proxyType === 'standalone' && (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              <strong>Standalone Mode:</strong> Only core CrowdSec features are available. 
              No proxy-level features like whitelist or captcha management are supported.
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  )
}