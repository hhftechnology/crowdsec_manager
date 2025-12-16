import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { ProxyType, Feature, FEATURE_DESCRIPTIONS } from '@/lib/proxy-types'
import { Link } from 'react-router-dom'
import {
  ListFilter,
  ScanFace,
  FileText,
  Shield,
  Activity,
  HeartPulse
} from 'lucide-react'

interface AdaptiveFeaturePanelProps {
  proxyType: ProxyType
  supportedFeatures: Feature[]
  className?: string
}

interface FeatureCardProps {
  title: string
  description: string
  icon: any
  available: boolean
  href: string
  proxyType: ProxyType
}

const FEATURE_ICONS: Record<Feature, any> = {
  whitelist: ListFilter,
  captcha: ScanFace,
  logs: FileText,
  bouncer: Shield,
  health: HeartPulse,
  appsec: Activity
}

const FEATURE_ROUTES: Record<Feature, string> = {
  whitelist: '/proxy-whitelist',
  captcha: '/captcha',
  logs: '/proxy-logs',
  bouncer: '/bouncers',
  health: '/health',
  appsec: '/appsec'
}

const FEATURE_TITLES: Record<Feature, string> = {
  whitelist: 'Whitelist Management',
  captcha: 'Captcha Protection',
  logs: 'Log Analysis',
  bouncer: 'Bouncer Integration',
  health: 'Health Monitoring',
  appsec: 'Application Security'
}

function FeatureCard({ 
  title, 
  description, 
  icon: Icon, 
  available, 
  href, 
  proxyType 
}: FeatureCardProps) {
  return (
    <Card className={cn(
      "transition-all hover:shadow-md",
      !available && "opacity-50"
    )}>
      <CardContent className="p-4">
        <div className="flex items-start justify-between mb-3">
          <Icon className={cn(
            "h-6 w-6", 
            available ? "text-primary" : "text-muted-foreground"
          )} />
          {available ? (
            <Badge variant="default" className="text-xs">
              Available
            </Badge>
          ) : (
            <Badge variant="secondary" className="text-xs">
              Not Supported
            </Badge>
          )}
        </div>
        
        <h3 className="font-semibold mb-1">{title}</h3>
        <p className="text-sm text-muted-foreground mb-3">{description}</p>
        
        {available ? (
          <Button asChild size="sm" className="w-full">
            <Link to={href}>Configure</Link>
          </Button>
        ) : (
          <Button size="sm" variant="outline" disabled className="w-full">
            Not Available for {proxyType.charAt(0).toUpperCase() + proxyType.slice(1)}
          </Button>
        )}
      </CardContent>
    </Card>
  )
}

export function AdaptiveFeaturePanel({ 
  proxyType, 
  supportedFeatures, 
  className 
}: AdaptiveFeaturePanelProps) {
  // Define all possible features to show
  const allFeatures: Feature[] = ['whitelist', 'captcha', 'logs', 'bouncer', 'health', 'appsec']
  
  return (
    <div className={cn(
      "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4",
      className
    )}>
      {allFeatures.map((feature) => {
        const Icon = FEATURE_ICONS[feature]
        const title = FEATURE_TITLES[feature]
        const description = FEATURE_DESCRIPTIONS[feature]
        const href = FEATURE_ROUTES[feature]
        const available = supportedFeatures.includes(feature)
        
        return (
          <FeatureCard
            key={feature}
            title={title}
            description={description}
            icon={Icon}
            available={available}
            href={href}
            proxyType={proxyType}
          />
        )
      })}
    </div>
  )
}