import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { ProxyType, PROXY_TYPES, FEATURE_DESCRIPTIONS, Feature } from '@/lib/proxy-types'
import {
  CheckCircle,
  XCircle,
  AlertTriangle,
  Info,
  ListFilter,
  ScanFace,
  FileText,
  Shield,
  Activity,
  HeartPulse
} from 'lucide-react'

interface FeaturePreviewProps {
  proxyType: ProxyType
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

export function FeaturePreview({ proxyType, className }: FeaturePreviewProps) {
  const proxyInfo = PROXY_TYPES.find(p => p.type === proxyType)
  
  if (!proxyInfo) {
    return null
  }

  const allFeatures: Feature[] = ['whitelist', 'captcha', 'logs', 'bouncer', 'health', 'appsec']
  const supportedFeatures = proxyInfo.features
  const unsupportedFeatures = allFeatures.filter(f => !supportedFeatures.includes(f))

  const getFeatureStatus = (feature: Feature) => {
    return supportedFeatures.includes(feature) ? 'supported' : 'unsupported'
  }

  const getStatusIcon = (status: 'supported' | 'unsupported') => {
    return status === 'supported' ? CheckCircle : XCircle
  }

  const getStatusColor = (status: 'supported' | 'unsupported') => {
    return status === 'supported' ? 'text-green-500' : 'text-red-500'
  }

  return (
    <div className={className}>
      <h4 className="text-base font-semibold mb-4">
        Feature Preview for {proxyInfo.name}
      </h4>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        {/* Supported Features */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-500" />
              Supported Features ({supportedFeatures.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {supportedFeatures.map(feature => {
              const Icon = FEATURE_ICONS[feature]
              const title = FEATURE_TITLES[feature]
              const description = FEATURE_DESCRIPTIONS[feature]
              
              return (
                <div key={feature} className="flex items-start gap-3">
                  <Icon className="h-4 w-4 text-green-500 mt-0.5" />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{title}</span>
                      <Badge variant="default" className="text-xs">
                        Available
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {description}
                    </p>
                  </div>
                </div>
              )
            })}
            
            {supportedFeatures.length === 0 && (
              <p className="text-sm text-muted-foreground">
                No additional features supported beyond basic health monitoring.
              </p>
            )}
          </CardContent>
        </Card>

        {/* Unsupported Features */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <XCircle className="h-4 w-4 text-red-500" />
              Not Supported ({unsupportedFeatures.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {unsupportedFeatures.map(feature => {
              const Icon = FEATURE_ICONS[feature]
              const title = FEATURE_TITLES[feature]
              const description = FEATURE_DESCRIPTIONS[feature]
              
              return (
                <div key={feature} className="flex items-start gap-3 opacity-60">
                  <Icon className="h-4 w-4 text-red-500 mt-0.5" />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{title}</span>
                      <Badge variant="secondary" className="text-xs">
                        Not Available
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {description}
                    </p>
                  </div>
                </div>
              )
            })}
            
            {unsupportedFeatures.length === 0 && (
              <p className="text-sm text-muted-foreground">
                All features are supported by this proxy type.
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Feature Summary */}
      <div className="space-y-3">
        <Alert>
          <Info className="h-4 w-4" />
          <AlertDescription>
            <strong>Feature Summary:</strong> {proxyInfo.name} supports {supportedFeatures.length} out of {allFeatures.length} available features. 
            {unsupportedFeatures.length > 0 && (
              <span> Features like {unsupportedFeatures.slice(0, 2).map(f => FEATURE_TITLES[f]).join(' and ')} will not be available.</span>
            )}
          </AlertDescription>
        </Alert>

        {proxyInfo.experimental && (
          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              <strong>Experimental Status:</strong> This proxy type is marked as experimental. 
              Some features may not work as expected and support may be limited.
            </AlertDescription>
          </Alert>
        )}

        {proxyType === 'standalone' && (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              <strong>Standalone Mode:</strong> This mode runs CrowdSec without any reverse proxy integration. 
              You'll have access to core CrowdSec features but no proxy-level controls.
            </AlertDescription>
          </Alert>
        )}
      </div>
    </div>
  )
}