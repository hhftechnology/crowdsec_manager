import { ProxyType } from '@/lib/proxy-types'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { 
  CheckCircle, 
  ExternalLink, 
  Shield, 
  Zap,
  Globe,
  Info
} from 'lucide-react'

interface CaptchaProvider {
  id: string
  name: string
  description: string
  icon: any
  supported: boolean
  recommended?: boolean
  website: string
  features: string[]
  pricing: string
}

interface CaptchaProviderSelectorProps {
  value: string
  onChange: (provider: string) => void
  proxyType: ProxyType
}

const CAPTCHA_PROVIDERS: CaptchaProvider[] = [
  {
    id: 'turnstile',
    name: 'Cloudflare Turnstile',
    description: 'Privacy-focused captcha with invisible challenges',
    icon: Shield,
    supported: true,
    recommended: true,
    website: 'https://www.cloudflare.com/products/turnstile/',
    features: ['Privacy-focused', 'Invisible challenges', 'High accuracy', 'Free tier available'],
    pricing: 'Free up to 1M requests/month'
  },
  {
    id: 'recaptcha',
    name: 'Google reCAPTCHA',
    description: 'Industry standard captcha solution',
    icon: Globe,
    supported: true,
    website: 'https://www.google.com/recaptcha/',
    features: ['Industry standard', 'Multiple challenge types', 'Risk analysis', 'Enterprise support'],
    pricing: 'Free up to 1M requests/month'
  },
  {
    id: 'hcaptcha',
    name: 'hCaptcha',
    description: 'Privacy-focused alternative to reCAPTCHA',
    icon: Zap,
    supported: true,
    website: 'https://www.hcaptcha.com/',
    features: ['Privacy compliant', 'GDPR/CCPA ready', 'Accessibility focused', 'Earn rewards'],
    pricing: 'Free up to 1M requests/month'
  }
]

export function CaptchaProviderSelector({ value, onChange, proxyType }: CaptchaProviderSelectorProps) {
  const getProviderCompatibility = (providerId: string): { compatible: boolean; notes?: string } => {
    // All providers are compatible with Traefik
    if (proxyType === 'traefik') {
      return { compatible: true }
    }

    // Other proxies don't support captcha middleware
    return { 
      compatible: false, 
      notes: `${proxyType} does not support captcha middleware integration` 
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <Label className="text-base font-medium">Captcha Provider</Label>
        <p className="text-sm text-muted-foreground mt-1">
          Select a captcha provider for your security challenges
        </p>
      </div>

      <div className="grid gap-4">
        {CAPTCHA_PROVIDERS.map((provider) => {
          const compatibility = getProviderCompatibility(provider.id)
          const isSelected = value === provider.id
          const Icon = provider.icon

          return (
            <Card 
              key={provider.id}
              className={`cursor-pointer transition-all ${
                isSelected 
                  ? 'ring-2 ring-primary border-primary' 
                  : 'hover:border-muted-foreground/50'
              } ${!compatibility.compatible ? 'opacity-60' : ''}`}
              onClick={() => compatibility.compatible && onChange(provider.id)}
            >
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${
                      isSelected ? 'bg-primary text-primary-foreground' : 'bg-muted'
                    }`}>
                      <Icon className="h-5 w-5" />
                    </div>
                    <div>
                      <CardTitle className="text-lg flex items-center gap-2">
                        {provider.name}
                        {provider.recommended && (
                          <Badge variant="secondary" className="text-xs">
                            Recommended
                          </Badge>
                        )}
                        {isSelected && (
                          <CheckCircle className="h-4 w-4 text-green-500" />
                        )}
                      </CardTitle>
                      <CardDescription>{provider.description}</CardDescription>
                    </div>
                  </div>
                  
                  <Button variant="ghost" size="sm" asChild>
                    <a 
                      href={provider.website} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  </Button>
                </div>
              </CardHeader>
              
              <CardContent className="space-y-3">
                <div>
                  <h4 className="font-medium text-sm mb-2">Features</h4>
                  <div className="flex flex-wrap gap-1">
                    {provider.features.map((feature, index) => (
                      <Badge key={index} variant="outline" className="text-xs">
                        {feature}
                      </Badge>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="font-medium text-sm mb-1">Pricing</h4>
                  <p className="text-xs text-muted-foreground">{provider.pricing}</p>
                </div>

                {!compatibility.compatible && compatibility.notes && (
                  <Alert>
                    <Info className="h-4 w-4" />
                    <AlertDescription className="text-xs">
                      {compatibility.notes}
                    </AlertDescription>
                  </Alert>
                )}
              </CardContent>
            </Card>
          )
        })}
      </div>

      {proxyType === 'traefik' && (
        <Alert>
          <Info className="h-4 w-4" />
          <AlertDescription>
            All captcha providers are supported with Traefik through the CrowdSec bouncer plugin. 
            Choose the provider that best fits your privacy and compliance requirements.
          </AlertDescription>
        </Alert>
      )}

      {proxyType !== 'traefik' && (
        <Alert>
          <Info className="h-4 w-4" />
          <AlertDescription>
            Captcha middleware is only supported with Traefik. Consider implementing captcha 
            protection at the application level or upgrading to Traefik for full middleware support.
          </AlertDescription>
        </Alert>
      )}
    </div>
  )
}