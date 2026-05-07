import { Button } from '@/components/ui/button'
import { DASHBOARD_RANGES, type DashboardRange } from '@/lib/api/dashboard'
import { cn } from '@/lib/utils'

interface RangeSelectorProps {
  value: DashboardRange
  onChange: (next: DashboardRange) => void
  className?: string
}

export function RangeSelector({ value, onChange, className }: RangeSelectorProps) {
  return (
    <div className={cn('inline-flex items-center gap-1 rounded-md bg-muted p-1', className)}>
      {DASHBOARD_RANGES.map((r) => (
        <Button
          key={r}
          size="sm"
          variant={value === r ? 'default' : 'ghost'}
          onClick={() => onChange(r)}
          className="h-7 px-3 text-xs"
        >
          {r}
        </Button>
      ))}
    </div>
  )
}
