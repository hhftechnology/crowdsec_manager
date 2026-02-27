import { useCallback, useState } from 'react'
import { cn } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import { Search } from 'lucide-react'

interface GlobalSearchProps {
  placeholder?: string
  onSearch: (query: string) => void
  className?: string
}

function GlobalSearch({
  placeholder = 'Search... (Ctrl+K)',
  onSearch,
  className,
}: GlobalSearchProps) {
  const [focused, setFocused] = useState(false)

  const handleFocus = useCallback(() => {
    setFocused(true)
    onSearch('')
  }, [onSearch])

  const handleBlur = useCallback(() => {
    setFocused(false)
  }, [])

  return (
    <div className={cn('relative', className)}>
      <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        placeholder={placeholder}
        onFocus={handleFocus}
        onBlur={handleBlur}
        readOnly
        className={cn(
          'cursor-pointer pl-9',
          focused && 'ring-2 ring-ring'
        )}
      />
      <kbd className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 rounded border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
        Ctrl+K
      </kbd>
    </div>
  )
}

export { GlobalSearch }
export type { GlobalSearchProps }
