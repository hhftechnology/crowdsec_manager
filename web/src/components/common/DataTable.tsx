import * as React from "react"
import { useState, useMemo } from "react"
import { ChevronDown, ChevronUp, ChevronsUpDown, Search, Filter, MoreHorizontal } from "lucide-react"
import { cn } from "@/lib/utils"
import { useBreakpoints } from "@/hooks/useMediaQuery"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Checkbox } from "@/components/ui/checkbox"
import { Card, CardContent } from "@/components/ui/card"
import { ScrollArea } from "@/components/ui/scroll-area"

export interface ColumnDef<T> {
  id: string
  header: string
  accessorKey?: keyof T
  cell?: (item: T) => React.ReactNode
  sortable?: boolean
  filterable?: boolean
  width?: string
  mobileHidden?: boolean // Hide column on mobile
  priority?: 'high' | 'medium' | 'low' // Column priority for responsive display
}

export interface PaginationConfig {
  page: number
  pageSize: number
  total: number
}

export interface SortingConfig {
  column: string
  direction: 'asc' | 'desc'
}

export interface FilteringConfig {
  column: string
  value: string
}

export interface SelectionConfig<T> {
  enabled: boolean
  selectedItems: T[]
  onSelectionChange: (items: T[]) => void
}

export interface DataTableProps<T> {
  data: T[]
  columns: ColumnDef<T>[]
  loading?: boolean
  pagination?: PaginationConfig
  onPaginationChange?: (pagination: PaginationConfig) => void
  sorting?: SortingConfig
  onSortingChange?: (sorting: SortingConfig) => void
  filtering?: FilteringConfig[]
  onFilteringChange?: (filtering: FilteringConfig[]) => void
  selection?: SelectionConfig<T>
  className?: string
  emptyMessage?: string
  mobileView?: 'table' | 'cards' | 'auto' // Mobile display mode
  cardRenderer?: (item: T, index: number) => React.ReactNode // Custom card renderer for mobile
}

export function DataTable<T extends Record<string, any>>({
  data,
  columns,
  loading = false,
  pagination,
  onPaginationChange,
  sorting,
  onSortingChange,
  filtering = [],
  onFilteringChange,
  selection,
  className,
  emptyMessage = "No data available",
  mobileView = 'auto',
  cardRenderer
}: DataTableProps<T>) {
  const [localSorting, setLocalSorting] = useState<SortingConfig | null>(null)
  const [localFiltering, setLocalFiltering] = useState<FilteringConfig[]>([])
  const [searchTerm, setSearchTerm] = useState("")

  const { isMobile, isTablet, needsTouchOptimization } = useBreakpoints()
  
  // Determine display mode
  const shouldShowCards = mobileView === 'cards' || (mobileView === 'auto' && isMobile)
  
  // Filter columns for responsive display
  const visibleColumns = useMemo(() => {
    if (!isMobile) return columns
    
    // On mobile, show high priority columns and hide mobileHidden columns
    return columns.filter(col => {
      if (col.mobileHidden) return false
      if (col.priority === 'high') return true
      if (col.priority === 'medium' && !isTablet) return false
      return col.priority !== 'low'
    })
  }, [columns, isMobile, isTablet])

  // Default card renderer for mobile view
  const defaultCardRenderer = (item: T, index: number) => {
    const primaryColumn = visibleColumns.find(col => col.priority === 'high') || visibleColumns[0]
    const secondaryColumns = visibleColumns.filter(col => col !== primaryColumn).slice(0, 2)
    
    return (
      <Card key={`mobile-card-${index}`} className="mb-3">
        <CardContent className="p-4">
          <div className="flex items-start justify-between mb-2">
            <div className="flex-1 min-w-0">
              <h4 className="font-medium truncate">
                {primaryColumn?.cell 
                  ? primaryColumn.cell(item)
                  : primaryColumn?.accessorKey 
                    ? String(item[primaryColumn.accessorKey] || '')
                    : ''
                }
              </h4>
            </div>
            {selection?.enabled && (
              <Checkbox
                checked={selection.selectedItems.some(selected => 
                  (selected.id || selected) === (item.id || item)
                )}
                onCheckedChange={(checked) => handleSelectItem(item, !!checked)}
                className="ml-2"
              />
            )}
          </div>
          
          {secondaryColumns.length > 0 && (
            <div className="space-y-1 text-sm text-muted-foreground">
              {secondaryColumns.map(column => (
                <div key={column.id} className="flex justify-between">
                  <span className="font-medium">{column.header}:</span>
                  <span className="text-right">
                    {column.cell 
                      ? column.cell(item)
                      : column.accessorKey 
                        ? String(item[column.accessorKey] || '')
                        : ''
                    }
                  </span>
                </div>
              ))}
            </div>
          )}
          
          {/* Show additional columns in dropdown on mobile */}
          {visibleColumns.length > 3 && (
            <div className="mt-3 pt-3 border-t">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="sm" className="w-full">
                    <MoreHorizontal className="h-4 w-4 mr-2" />
                    View Details
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start" className="w-56">
                  {visibleColumns.slice(3).map(column => (
                    <div key={column.id} className="px-2 py-1">
                      <div className="text-xs font-medium text-muted-foreground">
                        {column.header}
                      </div>
                      <div className="text-sm">
                        {column.cell 
                          ? column.cell(item)
                          : column.accessorKey 
                            ? String(item[column.accessorKey] || '')
                            : ''
                        }
                      </div>
                    </div>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          )}
        </CardContent>
      </Card>
    )
  }

  const currentSorting = sorting || localSorting
  const currentFiltering = filtering.length > 0 ? filtering : localFiltering

  // Apply filtering and sorting
  const processedData = useMemo(() => {
    let result = [...data]

    // Apply search filter
    if (searchTerm) {
      result = result.filter(item =>
        visibleColumns.some(column => {
          if (column.accessorKey) {
            const value = item[column.accessorKey]
            return String(value).toLowerCase().includes(searchTerm.toLowerCase())
          }
          return false
        })
      )
    }

    // Apply column filters
    currentFiltering.forEach(filter => {
      if (filter.value) {
        result = result.filter(item => {
          const column = visibleColumns.find(col => col.id === filter.column)
          if (column?.accessorKey) {
            const value = item[column.accessorKey]
            return String(value).toLowerCase().includes(filter.value.toLowerCase())
          }
          return true
        })
      }
    })

    // Apply sorting
    if (currentSorting) {
      const column = visibleColumns.find(col => col.id === currentSorting.column)
      if (column?.accessorKey) {
        result.sort((a, b) => {
          const aValue = a[column.accessorKey!]
          const bValue = b[column.accessorKey!]
          
          if (aValue < bValue) return currentSorting.direction === 'asc' ? -1 : 1
          if (aValue > bValue) return currentSorting.direction === 'asc' ? 1 : -1
          return 0
        })
      }
    }

    return result
  }, [data, visibleColumns, searchTerm, currentFiltering, currentSorting])

  // Pagination
  const paginatedData = useMemo(() => {
    if (!pagination) return processedData
    
    const start = (pagination.page - 1) * pagination.pageSize
    const end = start + pagination.pageSize
    return processedData.slice(start, end)
  }, [processedData, pagination])

  const handleSort = (columnId: string) => {
    const column = visibleColumns.find(col => col.id === columnId)
    if (!column?.sortable) return

    const newDirection = 
      currentSorting?.column === columnId && currentSorting.direction === 'asc' 
        ? 'desc' 
        : 'asc'
    
    const newSorting = { column: columnId, direction: newDirection }
    
    if (onSortingChange) {
      onSortingChange(newSorting)
    } else {
      setLocalSorting(newSorting)
    }
  }

  const handleFilter = (columnId: string, value: string) => {
    const newFiltering = currentFiltering.filter(f => f.column !== columnId)
    if (value) {
      newFiltering.push({ column: columnId, value })
    }
    
    if (onFilteringChange) {
      onFilteringChange(newFiltering)
    } else {
      setLocalFiltering(newFiltering)
    }
  }

  const handleSelectAll = (checked: boolean) => {
    if (!selection) return
    
    if (checked) {
      selection.onSelectionChange([...selection.selectedItems, ...paginatedData])
    } else {
      const currentPageIds = paginatedData.map(item => item.id || item)
      selection.onSelectionChange(
        selection.selectedItems.filter(item => 
          !currentPageIds.includes(item.id || item)
        )
      )
    }
  }

  const handleSelectItem = (item: T, checked: boolean) => {
    if (!selection) return
    
    if (checked) {
      selection.onSelectionChange([...selection.selectedItems, item])
    } else {
      selection.onSelectionChange(
        selection.selectedItems.filter(selected => 
          (selected.id || selected) !== (item.id || item)
        )
      )
    }
  }

  const isAllSelected = selection && paginatedData.length > 0 && 
    paginatedData.every(item => 
      selection.selectedItems.some(selected => 
        (selected.id || selected) === (item.id || item)
      )
    )

  const isIndeterminate = selection && 
    selection.selectedItems.length > 0 && 
    !isAllSelected

  if (loading) {
    return (
      <div className={cn("space-y-4", className)}>
        <div className="flex items-center justify-between">
          <div className="h-10 w-64 bg-muted animate-pulse rounded" />
          <div className="h-10 w-32 bg-muted animate-pulse rounded" />
        </div>
        
        {shouldShowCards ? (
          // Mobile card loading state
          <div className="space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <Card key={i} className="animate-pulse">
                <CardContent className="p-4">
                  <div className="h-5 w-3/4 bg-muted rounded mb-2" />
                  <div className="space-y-2">
                    <div className="h-4 w-1/2 bg-muted rounded" />
                    <div className="h-4 w-2/3 bg-muted rounded" />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : (
          // Table loading state
          <div className="border rounded-md">
            <div className="h-12 bg-muted animate-pulse" />
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="h-16 border-t bg-muted/50 animate-pulse" />
            ))}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className={cn("space-y-4", className)}>
      {/* Search and Filter Controls */}
      <div className={cn(
        "flex items-center gap-4",
        isMobile ? "flex-col space-y-3" : "justify-between"
      )}>
        <div className={cn(
          "flex items-center gap-2",
          isMobile ? "w-full" : "flex-1"
        )}>
          <div className={cn("relative", isMobile ? "flex-1" : "max-w-sm")}>
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className={cn(
                "pl-9",
                needsTouchOptimization && "min-h-[44px]"
              )}
              data-search-input
            />
          </div>
          
          {visibleColumns.some(col => col.filterable) && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button 
                  variant="outline" 
                  size={needsTouchOptimization ? "default" : "sm"}
                  className={needsTouchOptimization ? "min-h-[44px]" : ""}
                >
                  <Filter className="h-4 w-4 mr-2" />
                  {!isMobile && "Filters"}
                  {currentFiltering.length > 0 && (
                    <Badge variant="secondary" className="ml-2">
                      {currentFiltering.length}
                    </Badge>
                  )}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="w-56">
                {visibleColumns.filter(col => col.filterable).map(column => (
                  <div key={column.id} className="p-2">
                    <label className="text-sm font-medium">{column.header}</label>
                    <Input
                      placeholder={`Filter ${column.header.toLowerCase()}...`}
                      value={currentFiltering.find(f => f.column === column.id)?.value || ''}
                      onChange={(e) => handleFilter(column.id, e.target.value)}
                      className="mt-1"
                    />
                  </div>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>

        {selection && selection.selectedItems.length > 0 && (
          <Badge variant="secondary" className={isMobile ? "self-start" : ""}>
            {selection.selectedItems.length} selected
          </Badge>
        )}
      </div>

      {/* Data Display */}
      {shouldShowCards ? (
        // Mobile Card View
        <div className="space-y-3">
          {paginatedData.length === 0 ? (
            <Card>
              <CardContent className="p-8 text-center text-muted-foreground">
                {emptyMessage}
              </CardContent>
            </Card>
          ) : (
            paginatedData.map((item, index) => 
              cardRenderer ? cardRenderer(item, index) : defaultCardRenderer(item, index)
            )
          )}
        </div>
      ) : (
        // Table View
        <div className="border rounded-md overflow-hidden">
          <ScrollArea className="w-full">
            <Table>
              <TableHeader>
                <TableRow>
                  {selection?.enabled && (
                    <TableHead className="w-12">
                      <Checkbox
                        checked={isAllSelected}
                        indeterminate={isIndeterminate}
                        onCheckedChange={handleSelectAll}
                        aria-label="Select all"
                      />
                    </TableHead>
                  )}
                  {visibleColumns.map((column) => (
                    <TableHead 
                      key={column.id}
                      className={cn(
                        column.sortable && "cursor-pointer select-none hover:bg-muted/50",
                        column.width && `w-[${column.width}]`,
                        needsTouchOptimization && "min-h-[44px]"
                      )}
                      onClick={() => column.sortable && handleSort(column.id)}
                    >
                      <div className="flex items-center gap-2">
                        {column.header}
                        {column.sortable && (
                          <div className="flex flex-col">
                            {currentSorting?.column === column.id ? (
                              currentSorting.direction === 'asc' ? (
                                <ChevronUp className="h-4 w-4" />
                              ) : (
                                <ChevronDown className="h-4 w-4" />
                              )
                            ) : (
                              <ChevronsUpDown className="h-4 w-4 text-muted-foreground" />
                            )}
                          </div>
                        )}
                      </div>
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {paginatedData.length === 0 ? (
                  <TableRow>
                    <TableCell 
                      colSpan={visibleColumns.length + (selection?.enabled ? 1 : 0)} 
                      className="text-center py-8 text-muted-foreground"
                    >
                      {emptyMessage}
                    </TableCell>
                  </TableRow>
                ) : (
                  paginatedData.map((item, index) => {
                    const isSelected = selection?.selectedItems.some(selected => 
                      (selected.id || selected) === (item.id || item)
                    ) || false

                    return (
                      <TableRow 
                        key={`${item.id || 'item'}-${index}`} 
                        data-state={isSelected ? "selected" : undefined}
                        className={needsTouchOptimization ? "min-h-[44px]" : ""}
                      >
                        {selection?.enabled && (
                          <TableCell>
                            <Checkbox
                              checked={isSelected}
                              onCheckedChange={(checked) => handleSelectItem(item, !!checked)}
                              aria-label={`Select row ${index + 1}`}
                            />
                          </TableCell>
                        )}
                        {visibleColumns.map((column) => (
                          <TableCell key={column.id}>
                            {column.cell 
                              ? column.cell(item)
                              : column.accessorKey 
                                ? String(item[column.accessorKey] || '')
                                : ''
                            }
                          </TableCell>
                        ))}
                      </TableRow>
                    )
                  })
                )}
              </TableBody>
            </Table>
          </ScrollArea>
        </div>
      )}

      {/* Pagination */}
      {pagination && onPaginationChange && (
        <div className={cn(
          "flex items-center gap-4",
          isMobile ? "flex-col space-y-3" : "justify-between"
        )}>
          <div className="text-sm text-muted-foreground">
            Showing {Math.min((pagination.page - 1) * pagination.pageSize + 1, processedData.length)} to{' '}
            {Math.min(pagination.page * pagination.pageSize, processedData.length)} of{' '}
            {processedData.length} results
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size={needsTouchOptimization ? "default" : "sm"}
              disabled={pagination.page <= 1}
              onClick={() => onPaginationChange({
                ...pagination,
                page: pagination.page - 1
              })}
              className={needsTouchOptimization ? "min-h-[44px]" : ""}
            >
              Previous
            </Button>
            
            {/* Page numbers - simplified on mobile */}
            <div className="flex items-center gap-1">
              {isMobile ? (
                // Mobile: show current page info
                <span className="px-3 py-2 text-sm">
                  {pagination.page} / {Math.ceil(processedData.length / pagination.pageSize)}
                </span>
              ) : (
                // Desktop: show page buttons
                Array.from({ length: Math.ceil(processedData.length / pagination.pageSize) }, (_, i) => i + 1)
                  .filter(page => 
                    page === 1 || 
                    page === Math.ceil(processedData.length / pagination.pageSize) ||
                    Math.abs(page - pagination.page) <= 1
                  )
                  .map((page, index, array) => (
                    <React.Fragment key={page}>
                      {index > 0 && array[index - 1] !== page - 1 && (
                        <span className="px-2 text-muted-foreground">...</span>
                      )}
                      <Button
                        variant={page === pagination.page ? "default" : "outline"}
                        size="sm"
                        onClick={() => onPaginationChange({
                          ...pagination,
                          page
                        })}
                      >
                        {page}
                      </Button>
                    </React.Fragment>
                  ))
              )}
            </div>
            
            <Button
              variant="outline"
              size={needsTouchOptimization ? "default" : "sm"}
              disabled={pagination.page >= Math.ceil(processedData.length / pagination.pageSize)}
              onClick={() => onPaginationChange({
                ...pagination,
                page: pagination.page + 1
              })}
              className={needsTouchOptimization ? "min-h-[44px]" : ""}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}