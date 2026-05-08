import { Link } from 'react-router-dom'
import { Rocket, X, ArrowRight } from 'lucide-react'
import { useUpdateAvailable } from '@/hooks/useUpdateAvailable'

interface UpdateAvailableCardProps {
  collapsed?: boolean
}

export function UpdateAvailableCard({ collapsed = false }: UpdateAvailableCardProps) {
  const { available, services, dismissed, dismiss } = useUpdateAvailable()

  if (collapsed || !available || dismissed) return null

  const summary =
    services.length === 1
      ? `${services[0].name} has a newer image`
      : `${services.length} services have newer images`

  return (
    <div className="relative rounded-lg border border-sidebar-border bg-sidebar-accent/40 p-3 text-sidebar-foreground">
      <button
        type="button"
        onClick={dismiss}
        aria-label="Dismiss update notification"
        className="absolute top-1.5 right-1.5 rounded p-0.5 text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-foreground transition-colors"
      >
        <X className="h-3.5 w-3.5" />
      </button>
      <div className="flex items-center gap-2 text-sm font-semibold">
        <Rocket className="h-4 w-4 text-primary" />
        <span>Update Available</span>
      </div>
      <p className="mt-1 text-xs text-muted-foreground leading-snug">{summary}</p>
      <Link
        to="/update"
        className="mt-2 inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline"
      >
        View Release Notes
        <ArrowRight className="h-3 w-3" />
      </Link>
    </div>
  )
}
