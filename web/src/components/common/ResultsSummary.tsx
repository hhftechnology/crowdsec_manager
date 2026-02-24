import { Badge } from '@/components/ui/badge'

interface ResultsSummaryProps {
  total: number
  filtered?: number
  label: string
  query?: string
}

export function ResultsSummary({ total, filtered, label, query }: ResultsSummaryProps) {
  const hasFilter = typeof filtered === 'number' && filtered !== total
  const count = typeof filtered === 'number' ? filtered : total

  return (
    <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
      <div className="flex items-center gap-2">
        <Badge variant="secondary">{count}</Badge>
        <span>
          {hasFilter ? `${count} of ${total} ${label}` : `${total} ${label}`}
        </span>
      </div>
      {query && (
        <span>
          Filter: "{query}"
        </span>
      )}
    </div>
  )
}

export type { ResultsSummaryProps }
