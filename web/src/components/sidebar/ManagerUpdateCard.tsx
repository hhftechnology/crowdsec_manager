import { Rocket, X, ArrowRight } from 'lucide-react'
import { useManagerUpdate } from '@/hooks/useManagerUpdate'

interface ManagerUpdateCardProps {
  collapsed?: boolean
}

export function ManagerUpdateCard({ collapsed = false }: ManagerUpdateCardProps) {
  const { available, latestVersion, releaseUrl, dismissed, dismiss } = useManagerUpdate()

  if (collapsed || !available || dismissed || !latestVersion) return null

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
      <p className="mt-1 text-xs text-muted-foreground leading-snug">
        Version {latestVersion} of CrowdSec Manager is ready to install
      </p>
      {releaseUrl && (
        <a
          href={releaseUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-2 inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline"
        >
          View Release Notes
          <ArrowRight className="h-3 w-3" />
        </a>
      )}
    </div>
  )
}
