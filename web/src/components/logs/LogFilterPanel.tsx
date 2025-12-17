import { useState } from 'react'
import { ProxyType } from '@/lib/proxy-types'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Checkbox } from '@/components/ui/checkbox'
import { Separator } from '@/components/ui/separator'
import { 
  Filter, 
  Search, 
  X, 
  Calendar,
  AlertTriangle,
  Info,
  CheckCircle,
  XCircle
} from 'lucide-react'

export interface LogFilter {
  searchTerm: string
  logLevel: string[]
  timeRange: string
  statusCodes: string[]
  ipAddress: string
  httpMethod: string[]
  source: string[]
}

interface LogFilterPanelProps {
  proxyType: ProxyType
  onFilterChange: (filters: LogFilter) => void
  totalLogs: number
  filteredLogs: number
}

export function LogFilterPanel({ 
  proxyType, 
  onFilterChange, 
  totalLogs, 
  filteredLogs 
}: LogFilterPanelProps) {
  const [filters, setFilters] = useState<LogFilter>({
    searchTerm: '',
    logLevel: [],
    timeRange: 'all',
    statusCodes: [],
    ipAddress: '',
    httpMethod: [],
    source: []
  })

  const [isExpanded, setIsExpanded] = useState(false)

  const logLevels = ['ERROR', 'WARN', 'INFO', 'DEBUG']
  const statusCodeRanges = ['2xx', '3xx', '4xx', '5xx']
  const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
  const timeRanges = [
    { value: 'all', label: 'All Time' },
    { value: '1h', label: 'Last Hour' },
    { value: '6h', label: 'Last 6 Hours' },
    { value: '24h', label: 'Last 24 Hours' },
    { value: '7d', label: 'Last 7 Days' }
  ]

  const getAvailableSources = () => {
    const sources = ['crowdsec']
    
    if (proxyType !== 'standalone') {
      sources.push(proxyType)
    }
    
    return sources
  }

  const updateFilter = (key: keyof LogFilter, value: any) => {
    const newFilters = { ...filters, [key]: value }
    setFilters(newFilters)
    onFilterChange(newFilters)
  }

  const toggleArrayFilter = (key: keyof LogFilter, value: string) => {
    const currentArray = filters[key] as string[]
    const newArray = currentArray.includes(value)
      ? currentArray.filter(item => item !== value)
      : [...currentArray, value]
    
    updateFilter(key, newArray)
  }

  const clearAllFilters = () => {
    const emptyFilters: LogFilter = {
      searchTerm: '',
      logLevel: [],
      timeRange: 'all',
      statusCodes: [],
      ipAddress: '',
      httpMethod: [],
      source: []
    }
    setFilters(emptyFilters)
    onFilterChange(emptyFilters)
  }

  const hasActiveFilters = () => {
    return filters.searchTerm !== '' ||
           filters.logLevel.length > 0 ||
           filters.timeRange !== 'all' ||
           filters.statusCodes.length > 0 ||
           filters.ipAddress !== '' ||
           filters.httpMethod.length > 0 ||
           filters.source.length > 0
  }

  const getFilterCount = () => {
    let count = 0
    if (filters.searchTerm) count++
    if (filters.logLevel.length > 0) count++
    if (filters.timeRange !== 'all') count++
    if (filters.statusCodes.length > 0) count++
    if (filters.ipAddress) count++
    if (filters.httpMethod.length > 0) count++
    if (filters.source.length > 0) count++
    return count
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Filter className="h-5 w-5" />
              Log Filters
              {hasActiveFilters() && (
                <Badge variant="secondary" className="ml-2">
                  {getFilterCount()} active
                </Badge>
              )}
            </CardTitle>
            <CardDescription>
              Filter and search through log entries
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsExpanded(!isExpanded)}
            >
              {isExpanded ? 'Collapse' : 'Expand'}
            </Button>
            {hasActiveFilters() && (
              <Button
                variant="outline"
                size="sm"
                onClick={clearAllFilters}
              >
                <X className="h-4 w-4 mr-2" />
                Clear
              </Button>
            )}
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="space-y-4">
        {/* Results Summary */}
        <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm">
              Showing {filteredLogs.toLocaleString()} of {totalLogs.toLocaleString()} log entries
            </span>
          </div>
          {hasActiveFilters() && (
            <Badge variant="outline">
              Filtered
            </Badge>
          )}
        </div>

        {/* Search Term */}
        <div className="space-y-2">
          <Label htmlFor="search-term">Search Text</Label>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              id="search-term"
              placeholder="Search in log messages..."
              value={filters.searchTerm}
              onChange={(e) => updateFilter('searchTerm', e.target.value)}
              className="pl-10"
            />
          </div>
        </div>

        {isExpanded && (
          <>
            <Separator />

            {/* Log Levels */}
            <div className="space-y-2">
              <Label>Log Levels</Label>
              <div className="flex flex-wrap gap-2">
                {logLevels.map(level => (
                  <div key={level} className="flex items-center space-x-2">
                    <Checkbox
                      id={`level-${level}`}
                      checked={filters.logLevel.includes(level)}
                      onCheckedChange={() => toggleArrayFilter('logLevel', level)}
                    />
                    <Label 
                      htmlFor={`level-${level}`} 
                      className="flex items-center gap-1 cursor-pointer"
                    >
                      {level === 'ERROR' && <XCircle className="h-3 w-3 text-red-500" />}
                      {level === 'WARN' && <AlertTriangle className="h-3 w-3 text-yellow-500" />}
                      {level === 'INFO' && <Info className="h-3 w-3 text-blue-500" />}
                      {level === 'DEBUG' && <CheckCircle className="h-3 w-3 text-gray-500" />}
                      {level}
                    </Label>
                  </div>
                ))}
              </div>
            </div>

            {/* Time Range */}
            <div className="space-y-2">
              <Label htmlFor="time-range">Time Range</Label>
              <Select value={filters.timeRange} onValueChange={(value) => updateFilter('timeRange', value)}>
                <SelectTrigger id="time-range">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {timeRanges.map(range => (
                    <SelectItem key={range.value} value={range.value}>
                      <div className="flex items-center gap-2">
                        <Calendar className="h-4 w-4" />
                        {range.label}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* HTTP Status Codes (for proxy logs) */}
            {proxyType !== 'standalone' && (
              <div className="space-y-2">
                <Label>HTTP Status Codes</Label>
                <div className="flex flex-wrap gap-2">
                  {statusCodeRanges.map(range => (
                    <div key={range} className="flex items-center space-x-2">
                      <Checkbox
                        id={`status-${range}`}
                        checked={filters.statusCodes.includes(range)}
                        onCheckedChange={() => toggleArrayFilter('statusCodes', range)}
                      />
                      <Label htmlFor={`status-${range}`} className="cursor-pointer">
                        {range}
                      </Label>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* IP Address */}
            <div className="space-y-2">
              <Label htmlFor="ip-address">IP Address</Label>
              <Input
                id="ip-address"
                placeholder="Filter by IP address..."
                value={filters.ipAddress}
                onChange={(e) => updateFilter('ipAddress', e.target.value)}
                className="font-mono"
              />
            </div>

            {/* HTTP Methods (for proxy logs) */}
            {proxyType !== 'standalone' && (
              <div className="space-y-2">
                <Label>HTTP Methods</Label>
                <div className="flex flex-wrap gap-2">
                  {httpMethods.map(method => (
                    <div key={method} className="flex items-center space-x-2">
                      <Checkbox
                        id={`method-${method}`}
                        checked={filters.httpMethod.includes(method)}
                        onCheckedChange={() => toggleArrayFilter('httpMethod', method)}
                      />
                      <Label htmlFor={`method-${method}`} className="cursor-pointer font-mono text-sm">
                        {method}
                      </Label>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Log Sources */}
            <div className="space-y-2">
              <Label>Log Sources</Label>
              <div className="flex flex-wrap gap-2">
                {getAvailableSources().map(source => (
                  <div key={source} className="flex items-center space-x-2">
                    <Checkbox
                      id={`source-${source}`}
                      checked={filters.source.includes(source)}
                      onCheckedChange={() => toggleArrayFilter('source', source)}
                    />
                    <Label htmlFor={`source-${source}`} className="cursor-pointer capitalize">
                      {source}
                    </Label>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        {/* Active Filters Summary */}
        {hasActiveFilters() && (
          <>
            <Separator />
            <div className="space-y-2">
              <Label>Active Filters</Label>
              <div className="flex flex-wrap gap-2">
                {filters.searchTerm && (
                  <Badge variant="secondary" className="gap-1">
                    Search: "{filters.searchTerm}"
                    <X 
                      className="h-3 w-3 cursor-pointer" 
                      onClick={() => updateFilter('searchTerm', '')}
                    />
                  </Badge>
                )}
                {filters.logLevel.map(level => (
                  <Badge key={level} variant="secondary" className="gap-1">
                    Level: {level}
                    <X 
                      className="h-3 w-3 cursor-pointer" 
                      onClick={() => toggleArrayFilter('logLevel', level)}
                    />
                  </Badge>
                ))}
                {filters.timeRange !== 'all' && (
                  <Badge variant="secondary" className="gap-1">
                    Time: {timeRanges.find(r => r.value === filters.timeRange)?.label}
                    <X 
                      className="h-3 w-3 cursor-pointer" 
                      onClick={() => updateFilter('timeRange', 'all')}
                    />
                  </Badge>
                )}
                {filters.statusCodes.map(code => (
                  <Badge key={code} variant="secondary" className="gap-1">
                    Status: {code}
                    <X 
                      className="h-3 w-3 cursor-pointer" 
                      onClick={() => toggleArrayFilter('statusCodes', code)}
                    />
                  </Badge>
                ))}
                {filters.ipAddress && (
                  <Badge variant="secondary" className="gap-1">
                    IP: {filters.ipAddress}
                    <X 
                      className="h-3 w-3 cursor-pointer" 
                      onClick={() => updateFilter('ipAddress', '')}
                    />
                  </Badge>
                )}
                {filters.httpMethod.map(method => (
                  <Badge key={method} variant="secondary" className="gap-1">
                    Method: {method}
                    <X 
                      className="h-3 w-3 cursor-pointer" 
                      onClick={() => toggleArrayFilter('httpMethod', method)}
                    />
                  </Badge>
                ))}
                {filters.source.map(source => (
                  <Badge key={source} variant="secondary" className="gap-1">
                    Source: {source}
                    <X 
                      className="h-3 w-3 cursor-pointer" 
                      onClick={() => toggleArrayFilter('source', source)}
                    />
                  </Badge>
                ))}
              </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}