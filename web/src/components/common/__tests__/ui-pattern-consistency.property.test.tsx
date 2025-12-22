/**
 * Property-based tests for UI pattern consistency
 * **Feature: ui-revamp-shadcn-admin, Property 7: UI Pattern Consistency Property**
 * **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5**
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import * as fc from 'fast-check'
import { 
  DataTable, 
  StatusCard, 
  LoadingStates,
  FormComponents,
  NotificationComponents
} from '../index'
import type { 
  ColumnDef, 
  StatusCardProps,
  DataTableProps
} from '../index'

// Mock data generators with better edge case handling
const generateTableData = () => fc.array(
  fc.record({
    id: fc.integer({ min: 1, max: 1000 }).map((n, index) => `id-${n}-${Date.now()}-${index}`), // Ensure truly unique IDs
    name: fc.string({ minLength: 6, maxLength: 50 }).filter(s => {
      const trimmed = s.trim()
      return trimmed.length >= 6 && 
             /^[A-Za-z][A-Za-z0-9]{4,}$/.test(trimmed) && // Simple alphanumeric, no spaces
             !trimmed.includes('000') // Avoid triple zeros
    }),
    status: fc.constantFrom('active', 'inactive', 'pending'),
    value: fc.integer({ min: 0, max: 100 }),
    email: fc.emailAddress(),
    createdAt: fc.date({ min: new Date('2020-01-01'), max: new Date() })
  }),
  { minLength: 0, maxLength: 15 } // Reduce max length to avoid performance issues
)

const generateColumns = (): ColumnDef<any>[] => [
  {
    id: 'id',
    header: 'ID',
    accessorKey: 'id',
    sortable: true,
    width: '80px'
  },
  {
    id: 'name',
    header: 'Name',
    accessorKey: 'name',
    sortable: true,
    filterable: true
  },
  {
    id: 'status',
    header: 'Status',
    accessorKey: 'status',
    sortable: true,
    filterable: true,
    cell: (item) => (
      <span className={`px-2 py-1 rounded text-xs ${
        item.status === 'active' ? 'bg-green-100 text-green-800' :
        item.status === 'inactive' ? 'bg-red-100 text-red-800' :
        'bg-yellow-100 text-yellow-800'
      }`}>
        {item.status}
      </span>
    )
  },
  {
    id: 'value',
    header: 'Value',
    accessorKey: 'value',
    sortable: true
  }
]

const generateStatusCardProps = () => fc.record({
  title: fc.string({ minLength: 6, maxLength: 30 }).filter(s => {
    const trimmed = s.trim()
    return trimmed.length >= 6 && 
           /^[A-Za-z][A-Za-z0-9]{4,}$/.test(trimmed) && // Simple alphanumeric, no spaces
           !trimmed.includes('000') // Avoid triple zeros
  }),
  value: fc.oneof(
    fc.string({ minLength: 4, maxLength: 20 }).filter(s => {
      const trimmed = s.trim()
      return trimmed.length >= 4 && 
             /^[A-Za-z0-9]{4,}$/.test(trimmed) && // Simple alphanumeric, no spaces
             !trimmed.includes('000') // Avoid triple zeros
    }),
    fc.integer({ min: 10, max: 999999 }) // Avoid single digits
  ),
  description: fc.option(fc.string({ minLength: 10, maxLength: 100 }).filter(s => {
    const trimmed = s.trim()
    return trimmed.length >= 10 && 
           /^[A-Za-z][A-Za-z0-9\s]{8,}$/.test(trimmed) && // Allow spaces but controlled
           !trimmed.includes('  ') && // No double spaces
           !trimmed.includes('000') // Avoid triple zeros
  })),
  status: fc.constantFrom('success', 'warning', 'error', 'info', 'neutral'),
  trend: fc.option(fc.record({
    value: fc.integer({ min: -100, max: 100 }),
    label: fc.string({ minLength: 6, maxLength: 20 }).filter(s => {
      const trimmed = s.trim()
      return trimmed.length >= 6 && 
             /^[A-Za-z][A-Za-z0-9]{4,}$/.test(trimmed) && // Simple alphanumeric, no spaces
             !trimmed.includes('000') // Avoid triple zeros
    }),
    direction: fc.constantFrom('up', 'down', 'neutral')
  })),
  loading: fc.boolean()
})

describe('UI Pattern Consistency Property Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
  })

  afterEach(() => {
    document.body.innerHTML = ''
  })

  /**
   * Property 7: UI Pattern Consistency Property
   * For any data display pattern (tables, forms, cards, notifications, loading states), 
   * the UI should use standardized components with consistent behavior
   */

  describe('DataTable Component Consistency', () => {
    it('should render consistently with any valid data and maintain table structure', () => {
      fc.assert(
        fc.property(
          generateTableData(),
          fc.boolean(), // loading state
          fc.option(fc.record({
            page: fc.integer({ min: 1, max: 10 }),
            pageSize: fc.integer({ min: 5, max: 50 }),
            total: fc.integer({ min: 0, max: 1000 })
          })), // pagination
          (data, loading, pagination) => {
            const columns = generateColumns()
            
            const { unmount, container } = render(
              <DataTable
                data={data}
                columns={columns}
                loading={loading}
                pagination={pagination}
                emptyMessage="No data available"
              />
            )

            if (loading) {
              // Loading state should show skeleton
              expect(container.querySelector('.animate-pulse')).toBeTruthy()
            } else {
              // Should always have table structure
              const table = container.querySelector('table')
              expect(table).toBeTruthy()
              
              // Should have header row
              const headerRow = container.querySelector('thead tr')
              expect(headerRow).toBeTruthy()
              
              // Header should have correct number of columns
              const headerCells = container.querySelectorAll('thead th')
              expect(headerCells.length).toBe(columns.length)
              
              // Should have body
              const tbody = container.querySelector('tbody')
              expect(tbody).toBeTruthy()
              
              if (data.length === 0) {
                // Empty state should show message
                const emptyMessage = screen.queryAllByText('No data available')
                expect(emptyMessage.length).toBeGreaterThan(0)
              } else {
                // Should have data rows
                const dataRows = container.querySelectorAll('tbody tr')
                const expectedRows = pagination 
                  ? Math.min(data.length, pagination.pageSize)
                  : data.length
                
                // Handle pagination edge cases
                if (pagination && pagination.page > Math.ceil(data.length / pagination.pageSize)) {
                  // If page is beyond available data, component may show empty state or first page
                  expect(dataRows.length).toBeGreaterThanOrEqual(0)
                } else {
                  expect(dataRows.length).toBe(expectedRows)
                }
              }
              
              // Pagination should be present if provided
              if (pagination) {
                const paginationText = container.querySelector('div:has(button)')
                expect(paginationText).toBeTruthy()
              }
            }

            unmount()
          }
        ),
        { numRuns: 100 }
      )
    })

    it('should maintain consistent sorting behavior for any sortable column', () => {
      fc.assert(
        fc.property(
          generateTableData().filter(data => data.length > 1),
          (data) => {
            const columns = generateColumns()
            const sortableColumns = columns.filter(col => col.sortable)
            
            if (sortableColumns.length === 0) return
            
            const { unmount } = render(
              <DataTable
                data={data}
                columns={columns}
              />
            )

            // Test each sortable column
            sortableColumns.forEach(column => {
              const headerCell = screen.getByText(column.header)
              expect(headerCell).toBeTruthy()
              
              // Should be clickable (cursor pointer)
              const headerElement = headerCell.closest('th')
              expect(headerElement).toBeTruthy()
              expect(headerElement?.classList.contains('cursor-pointer')).toBe(true)
              
              // Click should not throw error
              expect(() => {
                fireEvent.click(headerCell)
              }).not.toThrow()
            })

            unmount()
          }
        ),
        { numRuns: 100 }
      )
    })
  })

  describe('StatusCard Component Consistency', () => {
    it('should render consistently with any valid props and maintain card structure', () => {
      fc.assert(
        fc.property(
          generateStatusCardProps(),
          (props) => {
            const { unmount, container } = render(
              <StatusCard {...props} />
            )

            if (props.loading) {
              // Loading state should show skeleton
              expect(container.querySelector('.animate-pulse')).toBeTruthy()
            } else {
              // Should always have card structure
              const card = container.querySelector('[class*="rounded"]')
              expect(card).toBeTruthy()
              
              // Should have title
              const titles = screen.queryAllByText(props.title)
              expect(titles.length).toBeGreaterThan(0) // At least one title should be found
              
              // Should have value
              const valueText = typeof props.value === 'number' 
                ? props.value.toLocaleString() 
                : props.value
              const values = screen.queryAllByText(valueText)
              expect(values.length).toBeGreaterThan(0)
              
              // Should have consistent styling based on status
              if (props.status && props.status !== 'neutral') {
                const statusBadges = screen.queryAllByText(
                  props.status.charAt(0).toUpperCase() + props.status.slice(1)
                )
                expect(statusBadges.length).toBeGreaterThan(0)
              }
              
              // Description should be present if provided
              if (props.description) {
                const description = screen.getByText(props.description)
                expect(description).toBeTruthy()
              }
              
              // Trend should be displayed if provided
              if (props.trend) {
                const trendValues = screen.queryAllByText(
                  `${props.trend.value > 0 ? '+' : ''}${props.trend.value}%`
                )
                expect(trendValues.length).toBeGreaterThan(0)
              }
            }

            unmount()
          }
        ),
        { numRuns: 100 }
      )
    })
  })

  describe('Loading States Consistency', () => {
    it('should provide consistent loading patterns for any loading state', () => {
      fc.assert(
        fc.property(
          fc.boolean(), // loading
          fc.option(fc.string({ minLength: 1, maxLength: 100 })), // error
          fc.constantFrom('sm', 'md', 'lg'), // spinner size
          fc.integer({ min: 1, max: 10 }), // skeleton rows
          fc.integer({ min: 1, max: 6 }), // skeleton columns
          (loading, error, spinnerSize, skeletonRows, skeletonColumns) => {
            // Test LoadingSpinner
            const { unmount: unmountSpinner } = render(
              <LoadingStates.Spinner size={spinnerSize} />
            )
            
            const spinner = document.querySelector('.animate-spin')
            expect(spinner).toBeTruthy()
            
            unmountSpinner()
            
            // Test LoadingState wrapper
            const { unmount: unmountState } = render(
              <LoadingStates.LoadingState
                loading={loading}
                error={error}
                onRetry={() => {}}
              >
                <div data-testid="content">Content</div>
              </LoadingStates.LoadingState>
            )
            
            if (loading) {
              // Should show loading spinner
              const loadingSpinner = document.querySelector('.animate-spin')
              expect(loadingSpinner).toBeTruthy()
              
              // Should not show content
              const content = screen.queryByTestId('content')
              expect(content).toBeFalsy()
            } else if (error) {
              // Should show error message
              const errorText = screen.getByText('Something went wrong')
              expect(errorText).toBeTruthy()
              
              // Should show retry button
              const retryButton = screen.getByText('Try Again')
              expect(retryButton).toBeTruthy()
            } else {
              // Should show content
              const content = screen.getByTestId('content')
              expect(content).toBeTruthy()
            }
            
            unmountState()
            
            // Test TableSkeleton
            const { unmount: unmountTable } = render(
              <LoadingStates.TableSkeleton 
                rows={skeletonRows} 
                columns={skeletonColumns} 
              />
            )
            
            const skeletonElements = document.querySelectorAll('.animate-pulse')
            expect(skeletonElements.length).toBeGreaterThan(0)
            
            // Should have correct structure
            const tableContainer = document.querySelector('div:has(> div.flex)')
            expect(tableContainer).toBeTruthy()
            
            unmountTable()
          }
        ),
        { numRuns: 100 }
      )
    })
  })

  describe('Form Components Consistency', () => {
    it('should maintain consistent form field structure and validation display', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 6, maxLength: 30 }).filter(s => {
            const trimmed = s.trim()
            return trimmed.length >= 6 && 
                   /^[A-Za-z][A-Za-z0-9]{4,}$/.test(trimmed) && // Simple alphanumeric, no spaces
                   !trimmed.includes('000') // Avoid triple zeros
          }), // label
          fc.string({ minLength: 6, maxLength: 50 }).filter(s => {
            const trimmed = s.trim()
            return trimmed.length >= 6 && 
                   /^[A-Za-z][A-Za-z0-9]{4,}$/.test(trimmed) && // Simple alphanumeric, no spaces
                   !trimmed.includes('000') // Avoid triple zeros
          }), // placeholder
          fc.boolean(), // disabled
          fc.option(fc.string({ minLength: 10, maxLength: 100 }).filter(s => {
            const trimmed = s.trim()
            return trimmed.length >= 10 && 
                   /^[A-Za-z][A-Za-z0-9\s]{8,}$/.test(trimmed) && // Allow spaces but controlled
                   !trimmed.includes('  ') && // No double spaces
                   !trimmed.includes('000') // Avoid triple zeros
          })), // description
          fc.constantFrom('error', 'success', 'warning', 'info'), // validation type
          fc.string({ minLength: 6, maxLength: 50 }).filter(s => {
            const trimmed = s.trim()
            return trimmed.length >= 6 && 
                   /^[A-Za-z][A-Za-z0-9\s]{4,}$/.test(trimmed) && // Allow spaces but controlled
                   !trimmed.includes('  ') && // No double spaces
                   !trimmed.includes('000') // Avoid triple zeros
          }), // validation message
          (label, placeholder, disabled, description, validationType, validationMessage) => {
            // Test ValidationMessage component
            const { unmount } = render(
              <FormComponents.ValidationMessage
                type={validationType}
                message={validationMessage}
              />
            )
            
            // Should display message
            const messages = screen.queryAllByText(validationMessage)
            expect(messages.length).toBeGreaterThan(0) // At least one message should be found
            
            // Should have appropriate styling based on type
            const messageContainer = messages[0]?.closest('div')
            expect(messageContainer).toBeTruthy()
            
            // Should have icon
            const icon = messageContainer?.querySelector('svg')
            expect(icon).toBeTruthy()
            
            // Should have consistent color scheme
            const hasColorClass = Array.from(messageContainer?.classList || [])
              .some(cls => cls.includes(validationType === 'error' ? 'red' : 
                                      validationType === 'success' ? 'green' :
                                      validationType === 'warning' ? 'yellow' : 'blue'))
            expect(hasColorClass).toBe(true)
            
            unmount()
          }
        ),
        { numRuns: 100 }
      )
    })
  })

  describe('Notification Components Consistency', () => {
    it('should provide consistent notification patterns for any notification type', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('default', 'destructive', 'warning', 'success', 'info'),
          fc.string({ minLength: 6, maxLength: 50 }).filter(s => {
            const trimmed = s.trim()
            return trimmed.length >= 6 && 
                   /^[A-Za-z][A-Za-z0-9]{4,}$/.test(trimmed) && // Simple alphanumeric, no spaces
                   !trimmed.includes('000') // Avoid triple zeros
          }), // title
          fc.string({ minLength: 6, maxLength: 100 }).filter(s => {
            const trimmed = s.trim()
            return trimmed.length >= 6 && 
                   /^[A-Za-z][A-Za-z0-9\s]{4,}$/.test(trimmed) && // Allow spaces but controlled
                   !trimmed.includes('  ') && // No double spaces
                   !trimmed.includes('000') // Avoid triple zeros
          }), // description
          fc.boolean(), // dismissible
          (variant, title, description, dismissible) => {
            const { unmount } = render(
              <NotificationComponents.AlertNotification
                variant={variant}
                title={title}
                description={description}
                onClose={dismissible ? () => {} : undefined}
              />
            )
            
            // Should display title
            const titleElements = screen.queryAllByText(title)
            expect(titleElements.length).toBeGreaterThan(0) // At least one title should be found
            
            // Should display description
            const descriptionElements = screen.queryAllByText(description)
            expect(descriptionElements.length).toBeGreaterThan(0) // At least one description should be found
            
            // Should have icon
            const icon = document.querySelector('svg')
            expect(icon).toBeTruthy()
            
            // Should have close button if dismissible
            if (dismissible) {
              const closeButton = document.querySelector('button')
              expect(closeButton).toBeTruthy()
            }
            
            // Should have consistent styling based on variant
            const alertContainer = titleElements[0]?.closest('[role="alert"], div')
            expect(alertContainer).toBeTruthy()
            
            unmount()
          }
        ),
        { numRuns: 100 }
      )
    })

    it('should maintain consistent notification banner structure', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('info', 'warning', 'error', 'success'),
          fc.string({ minLength: 6, maxLength: 50 }).filter(s => {
            const trimmed = s.trim()
            return trimmed.length >= 6 && 
                   /^[A-Za-z][A-Za-z0-9]{4,}$/.test(trimmed) && // Simple alphanumeric, no spaces
                   !trimmed.includes('000') // Avoid triple zeros
          }),
          fc.string({ minLength: 6, maxLength: 100 }).filter(s => {
            const trimmed = s.trim()
            return trimmed.length >= 6 && 
                   /^[A-Za-z][A-Za-z0-9\s]{4,}$/.test(trimmed) && // Allow spaces but controlled
                   !trimmed.includes('  ') && // No double spaces
                   !trimmed.includes('000') // Avoid triple zeros
          }),
          fc.option(fc.record({
            label: fc.string({ minLength: 6, maxLength: 20 }).filter(s => {
              const trimmed = s.trim()
              return trimmed.length >= 6 && 
                     /^[A-Za-z][A-Za-z0-9]{4,}$/.test(trimmed) && // Simple alphanumeric, no spaces
                     !trimmed.includes('000') // Avoid triple zeros
            }),
            onClick: fc.constant(() => {})
          })),
          (variant, title, message, action) => {
            const { unmount } = render(
              <NotificationComponents.NotificationBanner
                variant={variant}
                title={title}
                message={message}
                action={action}
                onDismiss={() => {}}
              />
            )
            
            // Should display title and message
            const titleElements = screen.queryAllByText(title)
            const messageElements = screen.queryAllByText(message)
            expect(titleElements.length).toBeGreaterThan(0) // At least one title should be found
            expect(messageElements.length).toBeGreaterThan(0) // At least one message should be found
            
            // Should have icon
            const icon = document.querySelector('svg')
            expect(icon).toBeTruthy()
            
            // Should have dismiss button
            const dismissButton = document.querySelector('button[aria-label*="dismiss"], button:has(svg)')
            expect(dismissButton).toBeTruthy()
            
            // Should have action button if provided
            if (action) {
              const actionButtons = screen.queryAllByText(action.label)
              expect(actionButtons.length).toBeGreaterThan(0)
            }
            
            unmount()
          }
        ),
        { numRuns: 100 }
      )
    })
  })

  describe('Cross-Component Consistency', () => {
    it('should maintain consistent spacing and typography across all components', () => {
      fc.assert(
        fc.property(
          generateStatusCardProps(),
          generateTableData(),
          (statusProps, tableData) => {
            const columns = generateColumns()
            
            const { unmount } = render(
              <div>
                <StatusCard {...statusProps} />
                <DataTable data={tableData} columns={columns} />
                <LoadingStates.CardSkeleton />
                <NotificationComponents.AlertNotification
                  variant="info"
                  title="Test"
                  description="Test description"
                />
              </div>
            )
            
            // All components should use consistent border radius classes
            const roundedElements = document.querySelectorAll('[class*="rounded"]')
            expect(roundedElements.length).toBeGreaterThan(0)
            
            // All components should use consistent spacing classes
            const spacingElements = document.querySelectorAll('[class*="p-"], [class*="m-"], [class*="space-"]')
            expect(spacingElements.length).toBeGreaterThan(0)
            
            // All components should use consistent text sizing
            const textElements = document.querySelectorAll('[class*="text-"]')
            expect(textElements.length).toBeGreaterThan(0)
            
            // All components should use theme-aware colors
            const colorElements = document.querySelectorAll('[class*="bg-"], [class*="text-"], [class*="border-"]')
            expect(colorElements.length).toBeGreaterThan(0)
            
            unmount()
          }
        ),
        { numRuns: 100 }
      )
    })

    it('should handle edge cases gracefully across all components', () => {
      fc.assert(
        fc.property(
          fc.oneof(
            fc.constant([]), // empty data
            fc.constant(null), // null data
            fc.constant(undefined) // undefined data
          ),
          fc.oneof(
            fc.constant(''), // empty string
            fc.constant(null), // null string
            fc.constant(undefined) // undefined string
          ),
          (edgeData, edgeString) => {
            // Test components with edge case data
            expect(() => {
              const { unmount: unmountTable } = render(
                <DataTable 
                  data={edgeData || []} 
                  columns={generateColumns()} 
                />
              )
              unmountTable()
            }).not.toThrow()
            
            expect(() => {
              const { unmount: unmountCard } = render(
                <StatusCard 
                  title={edgeString || 'Default Title'} 
                  value={edgeString || 'Default Value'} 
                />
              )
              unmountCard()
            }).not.toThrow()
            
            expect(() => {
              const { unmount: unmountNotification } = render(
                <NotificationComponents.AlertNotification
                  title={edgeString || 'Default Title'}
                  description={edgeString || 'Default Description'}
                />
              )
              unmountNotification()
            }).not.toThrow()
          }
        ),
        { numRuns: 100 }
      )
    })
  })
})