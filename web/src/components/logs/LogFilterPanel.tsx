import { useEffect, useState, useCallback } from 'react'
import { cn } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Search } from 'lucide-react'

interface LogFilters {
  service: string
  level: string
  search: string
}

interface LogFilterPanelProps {
  onFilterChange: (filters: LogFilters) => void
  services: string[]
  className?: string
  filters?: LogFilters
  includeAllServices?: boolean
}

const LOG_LEVELS = ['all', 'debug', 'info', 'warn', 'error', 'fatal'] as const

function LogFilterPanel({
  onFilterChange,
  services,
  className,
  filters: controlledFilters,
  includeAllServices = true,
}: LogFilterPanelProps) {
  const [filters, setFilters] = useState<LogFilters>(controlledFilters ?? {
    service: 'all',
    level: 'all',
    search: '',
  })

  useEffect(() => {
    if (controlledFilters) {
      setFilters(controlledFilters)
    }
  }, [controlledFilters])

  const updateFilter = useCallback(
    <K extends keyof LogFilters>(key: K, value: LogFilters[K]) => {
      const updated = { ...filters, [key]: value }
      setFilters(updated)
      onFilterChange(updated)
    },
    [filters, onFilterChange]
  )

  return (
    <div className={cn('flex flex-col gap-3 sm:flex-row sm:items-center', className)}>
      {/* Service selector */}
      <Select
        value={filters.service}
        onValueChange={(value) => updateFilter('service', value)}
      >
        <SelectTrigger className="w-full sm:w-[180px]">
          <SelectValue placeholder="Select service" />
        </SelectTrigger>
        <SelectContent>
          {includeAllServices && <SelectItem value="all">All Services</SelectItem>}
          {services.map((service) => (
            <SelectItem key={service} value={service}>
              {service}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {/* Log level filter */}
      <Select
        value={filters.level}
        onValueChange={(value) => updateFilter('level', value)}
      >
        <SelectTrigger className="w-full sm:w-[140px]">
          <SelectValue placeholder="Log level" />
        </SelectTrigger>
        <SelectContent>
          {LOG_LEVELS.map((level) => (
            <SelectItem key={level} value={level}>
              {level === 'all' ? 'All Levels' : level.charAt(0).toUpperCase() + level.slice(1)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {/* Search input */}
      <div className="relative flex-1">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search logs..."
          value={filters.search}
          onChange={(e) => updateFilter('search', e.target.value)}
          className="pl-9"
        />
      </div>
    </div>
  )
}

export { LogFilterPanel }
export type { LogFilterPanelProps, LogFilters }
