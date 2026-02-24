import { Badge } from '@/components/ui/badge'
import { Shield } from 'lucide-react'

interface ScenarioNameProps {
  scenario: string
  clickable?: boolean
  onClick?: () => void
}

/** Formats a CrowdSec scenario name (e.g. "crowdsecurity/ssh-bf") with collection badge */
export function ScenarioName({ scenario, clickable, onClick }: ScenarioNameProps) {
  if (!scenario) return <span className="text-muted-foreground">-</span>

  const parts = scenario.split('/')
  const collection = parts.length > 1 ? parts[0] : null
  const name = parts.length > 1 ? parts.slice(1).join('/') : scenario

  const content = (
    <span className="inline-flex items-center gap-1.5">
      <Shield className="h-3 w-3 text-muted-foreground flex-shrink-0" />
      {collection && (
        <Badge variant="outline" className="text-[10px] px-1 py-0 font-normal">
          {collection}
        </Badge>
      )}
      <span className="font-medium">{name}</span>
    </span>
  )

  if (clickable && onClick) {
    return (
      <button onClick={onClick} className="hover:underline text-left">
        {content}
      </button>
    )
  }

  return content
}
