import { cn } from '@/lib/utils'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { CheckCircle2, XCircle, type LucideIcon } from 'lucide-react'
import type { CaptchaStatus } from '@/lib/api'

interface CaptchaStatusMonitorProps {
  status: CaptchaStatus
  className?: string
}

interface StepInfo {
  label: string
  done: boolean
  icon: LucideIcon
}

function CaptchaStatusMonitor({ status, className }: CaptchaStatusMonitorProps) {
  const steps: StepInfo[] = [
    {
      label: 'Provider configured',
      done: !!status.provider || !!status.detectedProvider,
      icon: status.provider || status.detectedProvider ? CheckCircle2 : XCircle,
    },
    {
      label: 'Config saved',
      done: status.configSaved,
      icon: status.configSaved ? CheckCircle2 : XCircle,
    },
    {
      label: 'Captcha HTML exists',
      done: status.captchaHTMLExists,
      icon: status.captchaHTMLExists ? CheckCircle2 : XCircle,
    },
    {
      label: 'Fully implemented',
      done: status.implemented,
      icon: status.implemented ? CheckCircle2 : XCircle,
    },
  ]

  const providerName = status.provider ?? status.detectedProvider ?? status.savedProvider ?? 'None'

  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
        <CardTitle className="text-base">Captcha Status</CardTitle>
        <Badge variant={status.configured ? 'success' : 'secondary'}>
          {status.configured ? 'Configured' : 'Not Configured'}
        </Badge>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">Provider</span>
          <span className="font-medium">{providerName}</span>
        </div>

        <div className="space-y-3">
          {steps.map((step) => {
            const Icon = step.icon
            return (
              <div key={step.label} className="flex items-center gap-3">
                <Icon
                  className={cn(
                    'h-4 w-4',
                    step.done ? 'text-emerald-600 dark:text-emerald-400' : 'text-muted-foreground'
                  )}
                />
                <span
                  className={cn(
                    'text-sm',
                    step.done ? 'text-foreground' : 'text-muted-foreground'
                  )}
                >
                  {step.label}
                </span>
              </div>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}

export { CaptchaStatusMonitor }
export type { CaptchaStatusMonitorProps }
