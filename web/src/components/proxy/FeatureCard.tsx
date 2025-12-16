import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { Link } from 'react-router-dom'
import { LucideIcon } from 'lucide-react'

interface FeatureCardProps {
  title: string
  description: string
  icon: LucideIcon
  available: boolean
  href?: string
  proxyType?: string
  className?: string
  children?: React.ReactNode
}

export function FeatureCard({
  title,
  description,
  icon: Icon,
  available,
  href,
  proxyType,
  className,
  children
}: FeatureCardProps) {
  return (
    <Card className={cn(
      "transition-all hover:shadow-md",
      !available && "opacity-50",
      className
    )}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <Icon className={cn(
            "h-6 w-6",
            available ? "text-primary" : "text-muted-foreground"
          )} />
          <Badge 
            variant={available ? "default" : "secondary"} 
            className="text-xs"
          >
            {available ? "Available" : "Not Supported"}
          </Badge>
        </div>
        <CardTitle className="text-lg">{title}</CardTitle>
      </CardHeader>
      
      <CardContent>
        <p className="text-sm text-muted-foreground mb-4">{description}</p>
        
        {children}
        
        {href && (
          <div className="mt-4">
            {available ? (
              <Button asChild size="sm" className="w-full">
                <Link to={href}>Configure</Link>
              </Button>
            ) : (
              <Button size="sm" variant="outline" disabled className="w-full">
                Not Available{proxyType && ` for ${proxyType.charAt(0).toUpperCase() + proxyType.slice(1)}`}
              </Button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}