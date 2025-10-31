import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import api from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { AlertTriangle, Filter, RefreshCw, AlertCircle, Download, Info } from 'lucide-react'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'

interface AlertFilters {
  since?: string
  until?: string
  ip?: string
  range?: string
  scope?: string
  value?: string
  scenario?: string
  type?: string
  origin?: string
  includeAll?: boolean
}

export default function AlertAnalysis() {
  const [filters, setFilters] = useState<AlertFilters>({})
  const [activeFilters, setActiveFilters] = useState<AlertFilters>({})
  const [expandedAlert, setExpandedAlert] = useState<number | null>(null)

  const { data: alertsData, isLoading, refetch } = useQuery({
    queryKey: ['alerts-analysis', activeFilters],
    queryFn: async () => {
      const response = await api.crowdsec.getAlertsAnalysis(activeFilters)
      return response.data.data
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  const handleApplyFilters = () => {
    setActiveFilters(filters)
    toast.success('Filters applied')
  }

  const handleResetFilters = () => {
    setFilters({})
    setActiveFilters({})
    toast.info('Filters reset')
  }

  const handleExport = () => {
    if (!alertsData?.alerts || alertsData.alerts.length === 0) {
      toast.error('No data to export')
      return
    }

    const csvContent = [
      ['ID', 'Scenario', 'Scope', 'Value', 'Origin', 'Type', 'Events Count', 'Start At', 'Stop At'].join(','),
      ...alertsData.alerts.map((a: any) =>
        [
          a.id,
          a.scenario,
          a.scope,
          a.value,
          a.origin,
          a.type || 'N/A',
          a.events_count || 0,
          a.start_at,
          a.stop_at || 'Ongoing',
        ].join(',')
      ),
    ].join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `crowdsec-alerts-${new Date().toISOString()}.csv`
    a.click()
    window.URL.revokeObjectURL(url)
    toast.success('Alerts exported successfully')
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold flex items-center gap-2">
          <AlertTriangle className="h-8 w-8" />
          Alert List Analysis
        </h1>
        <p className="text-muted-foreground mt-2">
          Advanced filtering and analysis of CrowdSec alerts
        </p>
      </div>

      {/* Filters Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Filter className="h-5 w-5" />
            Filters
          </CardTitle>
          <CardDescription>
            Apply filters to analyze specific alerts based on CrowdSec criteria
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {/* Time-based Filters */}
            <div className="space-y-2">
              <Label htmlFor="since">Since (e.g., 4h, 30d)</Label>
              <Input
                id="since"
                placeholder="4h"
                value={filters.since || ''}
                onChange={(e) => setFilters({ ...filters, since: e.target.value })}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="until">Until (e.g., 1h, 7d)</Label>
              <Input
                id="until"
                placeholder="1h"
                value={filters.until || ''}
                onChange={(e) => setFilters({ ...filters, until: e.target.value })}
              />
            </div>

            {/* IP */}
            <div className="space-y-2">
              <Label htmlFor="ip">Source IP Address</Label>
              <Input
                id="ip"
                placeholder="192.168.1.100"
                value={filters.ip || ''}
                onChange={(e) => setFilters({ ...filters, ip: e.target.value })}
              />
            </div>

            {/* Range */}
            <div className="space-y-2">
              <Label htmlFor="range">IP Range (CIDR)</Label>
              <Input
                id="range"
                placeholder="192.168.1.0/24"
                value={filters.range || ''}
                onChange={(e) => setFilters({ ...filters, range: e.target.value })}
              />
            </div>

            {/* Scope */}
            <div className="space-y-2">
              <Label htmlFor="scope">Scope</Label>
              <Select
                value={filters.scope || ''}
                onValueChange={(value) => setFilters({ ...filters, scope: value })}
              >
                <SelectTrigger id="scope">
                  <SelectValue placeholder="All scopes" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All scopes</SelectItem>
                  <SelectItem value="ip">IP</SelectItem>
                  <SelectItem value="range">Range</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Value */}
            <div className="space-y-2">
              <Label htmlFor="value">Value</Label>
              <Input
                id="value"
                placeholder="Match specific value"
                value={filters.value || ''}
                onChange={(e) => setFilters({ ...filters, value: e.target.value })}
              />
            </div>

            {/* Scenario */}
            <div className="space-y-2">
              <Label htmlFor="scenario">Scenario</Label>
              <Input
                id="scenario"
                placeholder="crowdsecurity/ssh-bf"
                value={filters.scenario || ''}
                onChange={(e) => setFilters({ ...filters, scenario: e.target.value })}
              />
            </div>

            {/* Alert Type */}
            <div className="space-y-2">
              <Label htmlFor="type">Decision Type</Label>
              <Select
                value={filters.type || ''}
                onValueChange={(value) => setFilters({ ...filters, type: value })}
              >
                <SelectTrigger id="type">
                  <SelectValue placeholder="All types" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All types</SelectItem>
                  <SelectItem value="ban">Ban</SelectItem>
                  <SelectItem value="captcha">Captcha</SelectItem>
                  <SelectItem value="throttle">Throttle</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Origin */}
            <div className="space-y-2">
              <Label htmlFor="origin">Origin</Label>
              <Select
                value={filters.origin || ''}
                onValueChange={(value) => setFilters({ ...filters, origin: value })}
              >
                <SelectTrigger id="origin">
                  <SelectValue placeholder="All origins" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All origins</SelectItem>
                  <SelectItem value="cscli">cscli</SelectItem>
                  <SelectItem value="crowdsec">crowdsec</SelectItem>
                  <SelectItem value="console">console</SelectItem>
                  <SelectItem value="cscli-import">cscli-import</SelectItem>
                  <SelectItem value="lists">lists</SelectItem>
                  <SelectItem value="CAPI">CAPI</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Include All from Central API */}
          <div className="flex items-center space-x-2">
            <Checkbox
              id="includeAll"
              checked={filters.includeAll || false}
              onCheckedChange={(checked) =>
                setFilters({ ...filters, includeAll: checked as boolean })
              }
            />
            <Label
              htmlFor="includeAll"
              className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
            >
              Include alerts from Central API
            </Label>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-2 pt-2">
            <Button onClick={handleApplyFilters} className="flex-1">
              <Filter className="h-4 w-4 mr-2" />
              Apply Filters
            </Button>
            <Button onClick={handleResetFilters} variant="outline" className="flex-1">
              <RefreshCw className="h-4 w-4 mr-2" />
              Reset
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Results Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Alert Results</CardTitle>
              <CardDescription>
                {alertsData?.count || 0} alerts found
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => refetch()}
                disabled={isLoading}
              >
                <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
              <Button variant="outline" size="sm" onClick={handleExport}>
                <Download className="h-4 w-4 mr-2" />
                Export CSV
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
              <span className="ml-2 text-muted-foreground">Loading alerts...</span>
            </div>
          ) : alertsData?.alerts && alertsData.alerts.length > 0 ? (
            <div className="space-y-2">
              {alertsData.alerts.map((alert: any, index: number) => (
                <Collapsible
                  key={alert.id || index}
                  open={expandedAlert === index}
                  onOpenChange={() => setExpandedAlert(expandedAlert === index ? null : index)}
                >
                  <Card className="border-l-4 border-l-orange-500">
                    <CollapsibleTrigger className="w-full">
                      <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <AlertTriangle className="h-5 w-5 text-orange-500" />
                            <div className="text-left">
                              <CardTitle className="text-base">{alert.scenario}</CardTitle>
                              <CardDescription className="text-sm">
                                {alert.scope}: {alert.value}
                              </CardDescription>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant={alert.type === 'ban' ? 'destructive' : 'default'}>
                              {alert.type || 'Unknown'}
                            </Badge>
                            <Badge variant="secondary">{alert.origin}</Badge>
                            <Info className="h-4 w-4 text-muted-foreground" />
                          </div>
                        </div>
                      </CardHeader>
                    </CollapsibleTrigger>
                    <CollapsibleContent>
                      <CardContent>
                        <div className="grid gap-3 md:grid-cols-2 text-sm">
                          <div>
                            <span className="font-medium">Alert ID:</span>{' '}
                            <span className="text-muted-foreground">{alert.id}</span>
                          </div>
                          <div>
                            <span className="font-medium">Events Count:</span>{' '}
                            <span className="text-muted-foreground">{alert.events_count || 0}</span>
                          </div>
                          <div>
                            <span className="font-medium">Start Time:</span>{' '}
                            <span className="text-muted-foreground">
                              {new Date(alert.start_at).toLocaleString()}
                            </span>
                          </div>
                          <div>
                            <span className="font-medium">Stop Time:</span>{' '}
                            <span className="text-muted-foreground">
                              {alert.stop_at ? new Date(alert.stop_at).toLocaleString() : 'Ongoing'}
                            </span>
                          </div>
                          {alert.capacity && (
                            <div>
                              <span className="font-medium">Capacity:</span>{' '}
                              <span className="text-muted-foreground">{alert.capacity}</span>
                            </div>
                          )}
                          {alert.leakspeed && (
                            <div>
                              <span className="font-medium">Leak Speed:</span>{' '}
                              <span className="text-muted-foreground">{alert.leakspeed}</span>
                            </div>
                          )}
                          {alert.simulated !== undefined && (
                            <div>
                              <span className="font-medium">Simulated:</span>{' '}
                              <Badge variant={alert.simulated ? 'outline' : 'default'}>
                                {alert.simulated ? 'Yes' : 'No'}
                              </Badge>
                            </div>
                          )}
                          {alert.message && (
                            <div className="col-span-2">
                              <span className="font-medium">Message:</span>{' '}
                              <span className="text-muted-foreground">{alert.message}</span>
                            </div>
                          )}
                        </div>
                        {alert.decisions && alert.decisions.length > 0 && (
                          <div className="mt-4">
                            <h4 className="font-medium mb-2">Associated Decisions</h4>
                            <div className="rounded-md border">
                              <Table>
                                <TableHeader>
                                  <TableRow>
                                    <TableHead>Type</TableHead>
                                    <TableHead>Value</TableHead>
                                    <TableHead>Duration</TableHead>
                                    <TableHead>Scope</TableHead>
                                  </TableRow>
                                </TableHeader>
                                <TableBody>
                                  {alert.decisions.map((decision: any, idx: number) => (
                                    <TableRow key={idx}>
                                      <TableCell>
                                        <Badge
                                          variant={decision.type === 'ban' ? 'destructive' : 'default'}
                                        >
                                          {decision.type}
                                        </Badge>
                                      </TableCell>
                                      <TableCell className="font-mono text-sm">
                                        {decision.value}
                                      </TableCell>
                                      <TableCell>{decision.duration}</TableCell>
                                      <TableCell>
                                        <Badge variant="outline">{decision.scope}</Badge>
                                      </TableCell>
                                    </TableRow>
                                  ))}
                                </TableBody>
                              </Table>
                            </div>
                          </div>
                        )}
                      </CardContent>
                    </CollapsibleContent>
                  </Card>
                </Collapsible>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <AlertCircle className="h-12 w-12 text-muted-foreground mb-4" />
              <p className="text-lg font-medium">No alerts found</p>
              <p className="text-sm text-muted-foreground mt-2">
                Try adjusting your filters or check back later
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Information Card */}
      <Card>
        <CardHeader>
          <CardTitle>Filter Information</CardTitle>
          <CardDescription>Understanding alert list filters</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>
            <strong>Time Filters:</strong> Use duration format like 4h (4 hours), 30d (30 days), 1w (1 week)
          </p>
          <p>
            <strong>IP/Range:</strong> Filter alerts from specific source IPs or IP ranges (CIDR notation)
          </p>
          <p>
            <strong>Scope:</strong> Filter by scope (ip, range)
          </p>
          <p>
            <strong>Scenario:</strong> Filter by specific scenario (e.g., crowdsecurity/ssh-bf)
          </p>
          <p>
            <strong>Type:</strong> Filter alerts by their associated decision type (ban, captcha, throttle)
          </p>
          <p>
            <strong>Origin:</strong> Filter by alert source (cscli, crowdsec, console, lists, CAPI)
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
