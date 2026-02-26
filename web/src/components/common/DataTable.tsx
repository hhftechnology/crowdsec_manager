import { type ReactNode, useState, useMemo, useCallback } from 'react'
import { cn } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { EmptyState } from './ErrorStates'
import { ArrowDown, ArrowUp, ArrowUpDown, Search } from 'lucide-react'

type SortDirection = 'asc' | 'desc' | null

interface Column<T> {
  /** Unique key for the column, corresponding to a property on T or a custom id */
  key: string
  /** Display header label */
  header: string
  /** Custom render function for the cell */
  render?: (item: T) => ReactNode
  /** Whether this column is sortable (defaults to true) */
  sortable?: boolean
  /** Custom sort comparator */
  comparator?: (a: T, b: T) => number
  /** Optional class for the header cell */
  headerClassName?: string
  /** Optional class for body cells */
  cellClassName?: string
}

interface DataTableProps<T> {
  data: T[]
  columns: Column<T>[]
  searchable?: boolean
  searchKey?: keyof T & string
  searchPlaceholder?: string
  emptyTitle?: string
  emptyDescription?: string
  className?: string
  /** Unique key extractor for each row */
  rowKey?: (item: T, index: number) => string | number
}

function getNestedValue<T>(item: T, key: string): unknown {
  return (item as Record<string, unknown>)[key]
}

function DataTable<T>({
  data,
  columns,
  searchable = false,
  searchKey,
  searchPlaceholder = 'Search...',
  emptyTitle = 'No data found',
  emptyDescription = 'There are no items to display.',
  className,
  rowKey,
}: DataTableProps<T>) {
  const [searchQuery, setSearchQuery] = useState('')
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDirection, setSortDirection] = useState<SortDirection>(null)

  const handleSort = useCallback(
    (key: string) => {
      if (sortKey === key) {
        if (sortDirection === 'asc') {
          setSortDirection('desc')
        } else if (sortDirection === 'desc') {
          setSortKey(null)
          setSortDirection(null)
        }
      } else {
        setSortKey(key)
        setSortDirection('asc')
      }
    },
    [sortKey, sortDirection]
  )

  const filteredData = useMemo(() => {
    if (!searchable || !searchKey || !searchQuery.trim()) {
      return data
    }
    const query = searchQuery.toLowerCase()
    return data.filter((item) => {
      const value = getNestedValue(item, searchKey)
      return String(value ?? '').toLowerCase().includes(query)
    })
  }, [data, searchable, searchKey, searchQuery])

  const sortedData = useMemo(() => {
    if (!sortKey || !sortDirection) {
      return filteredData
    }

    const column = columns.find((col) => col.key === sortKey)
    if (!column) return filteredData

    return [...filteredData].sort((a, b) => {
      if (column.comparator) {
        const result = column.comparator(a, b)
        return sortDirection === 'desc' ? -result : result
      }

      const aVal = getNestedValue(a, sortKey)
      const bVal = getNestedValue(b, sortKey)
      const aStr = String(aVal ?? '')
      const bStr = String(bVal ?? '')
      const result = aStr.localeCompare(bStr, undefined, { numeric: true })
      return sortDirection === 'desc' ? -result : result
    })
  }, [filteredData, sortKey, sortDirection, columns])

  const getSortIcon = (key: string) => {
    if (sortKey !== key || !sortDirection) {
      return <ArrowUpDown className="ml-1 inline h-3 w-3 text-muted-foreground/50" />
    }
    if (sortDirection === 'asc') {
      return <ArrowUp className="ml-1 inline h-3 w-3" />
    }
    return <ArrowDown className="ml-1 inline h-3 w-3" />
  }

  return (
    <div className={cn('space-y-4', className)}>
      {searchable && searchKey && (
        <div className="relative max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder={searchPlaceholder}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9"
          />
        </div>
      )}

      {sortedData.length === 0 ? (
        <EmptyState
          title={emptyTitle}
          description={searchQuery ? `No results for "${searchQuery}".` : emptyDescription}
        />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              {columns.map((column) => {
                const isSortable = column.sortable !== false
                return (
                  <TableHead
                    key={column.key}
                    className={cn(
                      isSortable && 'cursor-pointer select-none',
                      column.headerClassName
                    )}
                    onClick={isSortable ? () => handleSort(column.key) : undefined}
                  >
                    {column.header}
                    {isSortable && getSortIcon(column.key)}
                  </TableHead>
                )
              })}
            </TableRow>
          </TableHeader>
          <TableBody>
            {sortedData.map((item, index) => {
              const key = rowKey ? rowKey(item, index) : index
              return (
                <TableRow key={key}>
                  {columns.map((column) => (
                    <TableCell key={column.key} className={column.cellClassName}>
                      {column.render
                        ? column.render(item)
                        : String(getNestedValue(item, column.key) ?? '')}
                    </TableCell>
                  ))}
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      )}
    </div>
  )
}

export { DataTable }
export type { DataTableProps, Column, SortDirection }
