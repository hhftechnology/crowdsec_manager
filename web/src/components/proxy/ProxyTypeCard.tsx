import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { ProxyInfo } from '@/lib/proxy-types'
import {
  Network,
  Server,
  Shield,
  Activity,
  Zap,
  Database
} from 'lucide-react'

interface ProxyTypeCardProps {
  proxy: ProxyInfo
  selected: boolean
  onSelect: (type: string) => void
  className?: string
}

const PROXY_ICONS = {
  Network,
  Server,
  Shield,
  Activity,
  Zap,
  Database
}

export function ProxyTypeCard({ 
  proxy, 
  selected, 
  onSelect, 
  className 
}: ProxyTypeCardProps) {
  const IconComponent = PROXY_ICONS[proxy.icon as keyof typeof PROXY_ICONS] || Network
  
  return (
    <Card 
      className={cn(
        "cursor-pointer transition-all hover:shadow-md",
        selected && "ring-2 ring-primary",
        className
      )}
      onClick={() => onSelect(proxy.type)}
    >
      <CardContent className="p-4 text-center">
        <div className="mb-3">
          <IconComponent className="h-8 w-8 mx-auto text-primary" />
        </div>
        
        <h3 className="font-semibold mb-1">{proxy.name}</h3>
        <p className="text-xs text-muted-foreground mb-2">{proxy.description}</p>
        
        <div className="flex flex-wrap gap-1 justify-center mb-2">
          {proxy.features.map((feature) => (
            <Badge key={feature} variant="secondary" className="text-xs">
              {feature}
            </Badge>
          ))}
        </div>
        
        {proxy.experimental && (
          <Badge variant="destructive" className="text-xs">
            Experimental
          </Badge>
        )}
        
        {selected && (
          <Badge variant="default" className="mt-2 text-xs">
            Selected
          </Badge>
        )}
      </CardContent>
    </Card>
  )
}