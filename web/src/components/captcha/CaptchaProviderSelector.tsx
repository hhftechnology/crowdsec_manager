import { cn } from '@/lib/utils'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { CheckCircle2, Shield } from 'lucide-react'

interface CaptchaProvider {
  id: string
  name: string
  description: string
}

const PROVIDERS: CaptchaProvider[] = [
  {
    id: 'turnstile',
    name: 'Cloudflare Turnstile',
    description: 'Privacy-focused CAPTCHA alternative by Cloudflare. No user interaction required in most cases.',
  },
]

interface CaptchaProviderSelectorProps {
  value: string
  onChange: (provider: string) => void
  className?: string
}

function CaptchaProviderSelector({ value, onChange, className }: CaptchaProviderSelectorProps) {
  return (
    <div className={cn('grid gap-4 sm:grid-cols-2', className)}>
      {PROVIDERS.map((provider) => {
        const isSelected = value === provider.id
        return (
          <Card
            key={provider.id}
            className={cn(
              'cursor-pointer transition-colors hover:border-primary/50',
              isSelected && 'border-primary ring-1 ring-primary'
            )}
            onClick={() => onChange(provider.id)}
          >
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="flex items-center gap-2 text-sm font-medium">
                <Shield className="h-4 w-4 text-primary" />
                {provider.name}
              </CardTitle>
              {isSelected && (
                <CheckCircle2 className="h-5 w-5 text-primary" />
              )}
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                {provider.description}
              </p>
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}

export { CaptchaProviderSelector, PROVIDERS }
export type { CaptchaProviderSelectorProps, CaptchaProvider }
