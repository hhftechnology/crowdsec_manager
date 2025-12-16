import { ProxyType, Feature, FEATURE_DESCRIPTIONS } from '@/lib/proxy-types'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { 
  CheckCircle, 
  XCircle, 
  AlertTriangle, 
  Info,
  Zap
} from 'lucide-react'

interface FeatureAvailabilityIndicatorProps {
  feature: Feature
  available: boolean
  proxyType: ProxyType
  description?: string
  showAlert?: boolean
}

export function FeatureAvailabilityIndicator({ 
  feature, 
  available, 
  proxyType, 
  description,
  showAlert = true 
}: FeatureAvailabilityIndicatorProps) {
  const proxyName = proxyType.charAt(0).toUpperCase() + proxyType.slice(1)
  const featureDescription = description || FEATURE_DESCRIPTIONS[feature]
  
  const getStatusIcon = () => {
    if (available) {
      return <CheckCircle className="h-4 w-4 text-green-500" />
    }
    if (proxyType === 'zoraxy') {
      return <AlertTriangle className="h-4 w-4 text-yellow-500" />
    }
    return <XCircle className="h-4 w-4 text-muted-foreground" />
  }

  const getStatusBadge = () => {
    if (available) {
      return <Badge variant="default" className="bg-green-100 text-green-800 border-green-200">Available</Badge>
    }
    if (proxyType === 'zoraxy') {
      return <Badge variant="secondary" className="bg-yellow-100 text-yellow-800 border-yellow-200">Experimental</Badge>
    }
    return <Badge variant="secondary" className="bg-gray-100 text-gray-600 border-gray-200">Not Available</Badge>
  }

  const getAlertVariant = () => {
    if (available) return 'default'
    if (proxyType === 'zoraxy') return 'default'
    return 'default'
  }

  const getAlertIcon = () => {
    if (available) return <CheckCircle className="h-4 w-4" />
    if (proxyType === 'zoraxy') return <Zap className="h-4 w-4" />
    return <Info className="h-4 w-4" />
  }

  const getAlertMessage = () => {
    if (available) {
      return `${proxyName} supports ${feature} management. ${featureDescription}`
    }
    
    if (proxyType === 'zoraxy') {
      return `${proxyName} has experimental support for ${feature}. Some features may be limited or unstable.`
    }

    // Specific messages for different proxy types and features
    const messages = {
      nginx: {
        whitelist: 'Nginx Proxy Manager does not support dynamic whitelist management through the API. Use NPM\'s web interface for access control.',
        captcha: 'Nginx Proxy Manager does not have built-in captcha middleware. Consider using external captcha solutions.',
        logs: 'Log parsing is available for Nginx Proxy Manager access logs.',
      },
      caddy: {
        whitelist: 'Caddy does not have built-in whitelist middleware. Consider using the request_header matcher or external plugins.',
        captcha: 'Caddy does not have built-in captcha middleware. Use external captcha solutions or custom plugins.',
        logs: 'Caddy log parsing is not currently implemented. Use Caddy\'s built-in logging features.',
      },
      haproxy: {
        whitelist: 'HAProxy does not support dynamic whitelist management through CrowdSec Manager. Configure ACLs directly in HAProxy configuration.',
        captcha: 'HAProxy does not have built-in captcha support. Implement captcha at the application level.',
        logs: 'HAProxy log parsing is not currently implemented. Use HAProxy\'s built-in logging features.',
      },
      standalone: {
        whitelist: 'Standalone mode operates without a reverse proxy, so proxy-level whitelisting is not applicable.',
        captcha: 'Standalone mode operates without a reverse proxy, so proxy-level captcha is not applicable.',
        logs: 'Standalone mode operates without a reverse proxy, so proxy log parsing is not applicable.',
      }
    }

    return messages[proxyType]?.[feature] || `${proxyName} does not support ${feature} management.`
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between p-3 border rounded-lg">
        <div className="flex items-center gap-3">
          {getStatusIcon()}
          <div>
            <p className="font-medium capitalize">{feature} Management</p>
            <p className="text-sm text-muted-foreground">{featureDescription}</p>
          </div>
        </div>
        {getStatusBadge()}
      </div>

      {showAlert && (
        <Alert variant={getAlertVariant()}>
          {getAlertIcon()}
          <AlertDescription>
            {getAlertMessage()}
          </AlertDescription>
        </Alert>
      )}
    </div>
  )
}