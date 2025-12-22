import React from 'react'
import { cn } from '@/lib/utils'
import { useBreakpoints } from '@/hooks/useMediaQuery'
import { DataTable, DataTableProps, ColumnDef } from './DataTable'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { MoreHorizontal } from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

interface ResponsiveTableProps<T> extends Omit<DataTableProps<T>, 'mobileView' | 'cardRenderer'> {
  title?: string
  description?: string
  mobileCardFields?: {
    primary: keyof T
    secondary?: (keyof T)[]
    actions?: (item: T) => React.ReactNode
  }
  forceTableView?: boolean
}

export function ResponsiveTable<T extends Record<string, any>>({
  title,
  description,
  mobileCardFields,
  forceTableView = false,
  columns,
  data,
  className,
  ...props
}: ResponsiveTableProps<T>) {
  const { isMobile } = useBreakpoints()
  // const needsTouchOptimization = useBreakpoints().needsTouchOptimization // Unused variable

  // Enhanced columns with responsive priorities
  const enhancedColumns: ColumnDef<T>[] = React.useMemo(() => {
    return columns.map((col, index) => ({
      ...col,
      priority: col.priority || (index === 0 ? 'high' : index < 3 ? 'medium' : 'low'),
      mobileHidden: col.mobileHidden || (index > 2 && !col.priority)
    }))
  }, [columns])

  // Custom mobile card renderer
  const mobileCardRenderer = React.useCallback((item: T, index: number) => {
    if (!mobileCardFields) return null

    const primaryValue = item[mobileCardFields.primary]
    const secondaryFields = mobileCardFields.secondary || []

    return (
      <Card key={`mobile-card-${index}`} className="mb-3">
        <CardContent className="p-4">
          <div className="flex items-start justify-between mb-3">
            <div className="flex-1 min-w-0">
              <h4 className="font-medium text-base truncate">
                {String(primaryValue || '')}
              </h4>
            </div>
            
            {/* Actions dropdown */}
            {mobileCardFields.actions && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button 
                    variant="ghost" 
                    size="icon" 
                    className="h-8 w-8 ml-2 flex-shrink-0"
                  >
                    <MoreHorizontal className="h-4 w-4" />
                    <span className="sr-only">Open actions</span>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  {mobileCardFields.actions(item)}
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </div>
          
          {/* Secondary fields */}
          {secondaryFields.length > 0 && (
            <div className="space-y-2">
              {secondaryFields.slice(0, 3).map(field => {
                const column = enhancedColumns.find(col => col.accessorKey === field)
                const value = item[field]
                
                return (
                  <div key={String(field)} className="flex justify-between items-center text-sm">
                    <span className="text-muted-foreground font-medium">
                      {column?.header || String(field)}:
                    </span>
                    <span className="text-right">
                      {column?.cell ? column.cell(item) : String(value || '')}
                    </span>
                  </div>
                )
              })}
            </div>
          )}
          
          {/* Show more fields if available */}
          {secondaryFields.length > 3 && (
            <div className="mt-3 pt-3 border-t">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="sm" className="w-full">
                    <MoreHorizontal className="h-4 w-4 mr-2" />
                    View More Details
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start" className="w-64">
                  {secondaryFields.slice(3).map(field => {
                    const column = enhancedColumns.find(col => col.accessorKey === field)
                    const value = item[field]
                    
                    return (
                      <div key={String(field)} className="px-2 py-2 border-b last:border-0">
                        <div className="text-xs font-medium text-muted-foreground mb-1">
                          {column?.header || String(field)}
                        </div>
                        <div className="text-sm">
                          {column?.cell ? column.cell(item) : String(value || '')}
                        </div>
                      </div>
                    )
                  })}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          )}
        </CardContent>
      </Card>
    )
  }, [mobileCardFields, enhancedColumns])

  const shouldShowMobileCards = isMobile && !forceTableView && mobileCardFields

  return (
    <div className={cn("space-y-4", className)}>
      {/* Header */}
      {(title || description) && (
        <div>
          {title && (
            <h2 className={cn(
              "font-semibold",
              isMobile ? "text-lg" : "text-xl"
            )}>
              {title}
            </h2>
          )}
          {description && (
            <p className="text-muted-foreground mt-1 text-sm">
              {description}
            </p>
          )}
        </div>
      )}

      {/* Table/Cards */}
      <DataTable
        columns={enhancedColumns}
        data={data}
        mobileView={shouldShowMobileCards ? 'cards' : 'table'}
        cardRenderer={shouldShowMobileCards ? mobileCardRenderer : undefined}
        {...props}
      />
    </div>
  )
}

// Utility function to create responsive column definitions
export function createResponsiveColumns<T>(
  baseColumns: Omit<ColumnDef<T>, 'priority' | 'mobileHidden'>[],
  options: {
    primaryColumn?: number
    mobileVisibleColumns?: number[]
    hiddenOnMobile?: number[]
  } = {}
): ColumnDef<T>[] {
  const { primaryColumn = 0, mobileVisibleColumns = [0, 1], hiddenOnMobile = [] } = options

  return baseColumns.map((col, index) => ({
    ...col,
    priority: index === primaryColumn ? 'high' : 
             mobileVisibleColumns.includes(index) ? 'medium' : 'low',
    mobileHidden: hiddenOnMobile.includes(index)
  }))
}

export default ResponsiveTable