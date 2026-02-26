import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Checkbox } from '@/components/ui/checkbox'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Filter, RefreshCw } from 'lucide-react'

interface FilterField {
  id: string
  label: string
  type: 'input' | 'select'
  placeholder?: string
  options?: { value: string; label: string }[]
}

interface CrowdSecFilterFormProps {
  fields: FilterField[]
  filters: Record<string, string | boolean | undefined>
  onFilterChange: (key: string, value: string | boolean) => void
  onApply: () => void
  onReset: () => void
  title?: string
  description?: string
  showIncludeAll?: boolean
  includeAllLabel?: string
}

const SCOPE_OPTIONS = [
  { value: 'all', label: 'All scopes' },
  { value: 'ip', label: 'IP' },
  { value: 'range', label: 'Range' },
]

const TYPE_OPTIONS = [
  { value: 'all', label: 'All types' },
  { value: 'ban', label: 'Ban' },
  { value: 'captcha', label: 'Captcha' },
  { value: 'throttle', label: 'Throttle' },
]

const ORIGIN_OPTIONS = [
  { value: 'all', label: 'All origins' },
  { value: 'cscli', label: 'cscli' },
  { value: 'crowdsec', label: 'crowdsec' },
  { value: 'console', label: 'console' },
  { value: 'cscli-import', label: 'cscli-import' },
  { value: 'lists', label: 'lists' },
  { value: 'CAPI', label: 'CAPI' },
]

function CrowdSecFilterForm({
  fields,
  filters,
  onFilterChange,
  onApply,
  onReset,
  title = 'Filters',
  description = 'Apply filters to analyze specific data based on CrowdSec criteria',
  showIncludeAll = false,
  includeAllLabel = 'Include from Central API',
}: CrowdSecFilterFormProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Filter className="h-5 w-5" />
          {title}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {fields.map((field) => (
            <div key={field.id} className="space-y-2">
              <Label htmlFor={field.id}>{field.label}</Label>
              {field.type === 'input' ? (
                <Input
                  id={field.id}
                  placeholder={field.placeholder}
                  value={(filters[field.id] as string) || ''}
                  onChange={(e) => onFilterChange(field.id, e.target.value)}
                />
              ) : (
                <Select
                  value={(filters[field.id] as string) || ''}
                  onValueChange={(value) => onFilterChange(field.id, value)}
                >
                  <SelectTrigger id={field.id}>
                    <SelectValue placeholder={field.options?.[0]?.label || 'Select...'} />
                  </SelectTrigger>
                  <SelectContent>
                    {field.options?.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>
                        {opt.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
          ))}
        </div>

        {showIncludeAll && (
          <div className="flex items-center space-x-2">
            <Checkbox
              id="includeAll"
              checked={(filters.includeAll as boolean) || false}
              onCheckedChange={(checked) => onFilterChange('includeAll', checked as boolean)}
            />
            <Label
              htmlFor="includeAll"
              className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
            >
              {includeAllLabel}
            </Label>
          </div>
        )}

        <div className="flex gap-2 pt-2">
          <Button onClick={onApply} className="flex-1">
            <Filter className="h-4 w-4 mr-2" />
            Apply Filters
          </Button>
          <Button onClick={onReset} variant="outline" className="flex-1">
            <RefreshCw className="h-4 w-4 mr-2" />
            Reset
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

export { CrowdSecFilterForm, SCOPE_OPTIONS, TYPE_OPTIONS, ORIGIN_OPTIONS }
export type { CrowdSecFilterFormProps, FilterField }
