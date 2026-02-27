import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider } from '@/components/ui/tooltip'

function relativeTime(dateStr: string): string {
  const now = Date.now()
  const then = new Date(dateStr).getTime()
  const diff = now - then
  if (isNaN(then)) return dateStr

  const seconds = Math.floor(diff / 1000)
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days}d ago`
  const months = Math.floor(days / 30)
  return `${months}mo ago`
}

interface TimeDisplayProps {
  date: string
  className?: string
}

/** Relative time display ("2h ago") with tooltip for absolute time */
export function TimeDisplay({ date, className }: TimeDisplayProps) {
  if (!date) return <span className="text-muted-foreground">-</span>

  const absolute = new Date(date).toLocaleString()
  const relative = relativeTime(date)

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <time dateTime={date} className={className}>
            {relative}
          </time>
        </TooltipTrigger>
        <TooltipContent>
          <p>{absolute}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

/** Format duration to human-readable (e.g., "3h45m" → "3 hours 45 minutes") */
export function formatDuration(duration: string): string {
  if (!duration) return '-'
  // Parse Go-style durations like "4h0m0s", "168h0m0s", "3h45m3s"
  const match = duration.match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/)
  if (!match) return duration

  const hours = parseInt(match[1] || '0')
  const minutes = parseInt(match[2] || '0')

  if (hours >= 8760) return `${Math.floor(hours / 8760)}y`
  if (hours >= 720) return `${Math.floor(hours / 720)}mo`
  if (hours >= 168) return `${Math.floor(hours / 168)}w`
  if (hours >= 24) return `${Math.floor(hours / 24)}d ${hours % 24}h`
  if (hours > 0) return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`
  if (minutes > 0) return `${minutes}m`
  return '<1m'
}

/** Compute and format expiration countdown */
export function expiresIn(untilStr: string): string {
  if (!untilStr) return '-'
  const until = new Date(untilStr).getTime()
  const now = Date.now()
  if (isNaN(until)) return untilStr

  const diff = until - now
  if (diff <= 0) return 'Expired'

  const hours = Math.floor(diff / 3600000)
  const minutes = Math.floor((diff % 3600000) / 60000)
  if (hours >= 24) return `${Math.floor(hours / 24)}d ${hours % 24}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  return `${minutes}m`
}
