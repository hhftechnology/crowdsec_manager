import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { Decision } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Shield, Filter, RefreshCw, AlertCircle, Download } from 'lucide-react'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

interface DecisionFilters {
  since?: string
  until?: string
  type?: string
  scope?: string
  origin?: string
  value?: string
  scenario?: string
  ip?: string
  range?: string
  includeAll?: boolean
}

export default function DecisionAnalysis() {
  const [filters, setFilters] = useState<DecisionFilters>({})
  const [activeFilters, setActiveFilters] = useState<DecisionFilters>({})

  const { data: decisionsData, isLoading, refetch } = useQuery({
    queryKey: ['decisions-analysis', activeFilters],
    queryFn: async () => {
      const response = await api.crowdsec.getDecisionsAnalysis(activeFilters)
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
    if (!decisionsData?.decisions || decisionsData.decisions.length === 0) {
      toast.error('No data to export')
      return
    }

    const csvContent = [
      ['ID', 'Alert ID', 'Type', 'Scope', 'Value', 'Origin', 'Scenario', 'Duration', 'Created At'].join(','),
      ...decisionsData.decisions.map((d: Decision) =>
        [d.id, d.alert_id, d.type, d.scope, d.value, d.origin, d.scenario, d.duration, d.created_at].join(',')
      ),
    ].join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `crowdsec-decisions-${new Date().toISOString()}.csv`
    a.click()
    window.URL.revokeObjectURL(url)
    toast.success('Decisions exported successfully')
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold flex items-center gap-2">
          <Shield className="h-8 w-8" />
          Decision List Analysis
        </h1>
        <p className="text-muted-foreground mt-2">
          Advanced filtering and analysis of CrowdSec decisions
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
            Apply filters to analyze specific decisions based on CrowdSec criteria
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

            {/* Decision Type */}
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
                  <SelectItem value="session">Session</SelectItem>
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

            {/* Value */}
            <div className="space-y-2">
              <Label htmlFor="value">Value (IP, username, etc.)</Label>
              <Input
                id="value"
                placeholder="1.2.3.4"
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

            {/* IP */}
            <div className="space-y-2">
              <Label htmlFor="ip">IP Address</Label>
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
              Include decisions from Central API
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
              <CardTitle>Decision Results</CardTitle>
              <CardDescription>
                {decisionsData?.count || 0} decisions found
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
              <span className="ml-2 text-muted-foreground">Loading decisions...</span>
            </div>
          ) : decisionsData?.decisions && decisionsData.decisions.length > 0 ? (
            <div className="rounded-md border overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ID</TableHead>
                    <TableHead>Alert ID</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Scope</TableHead>
                    <TableHead>Value</TableHead>
                    <TableHead>Origin</TableHead>
                    <TableHead>Scenario</TableHead>
                    <TableHead>Duration</TableHead>
                    <TableHead>Expires</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {decisionsData.decisions.map((decision: Decision, index: number) => (
                    <TableRow key={decision.id || index}>
                      <TableCell className="font-mono text-xs">{decision.id}</TableCell>
                      <TableCell className="font-mono text-xs">{decision.alert_id}</TableCell>
                      <TableCell>
                        <Badge variant={decision.type === 'ban' ? 'destructive' : 'default'}>
                          {decision.type}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{decision.scope}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-sm">{decision.value}</TableCell>
                      <TableCell>
                        <Badge variant="secondary">{decision.origin}</Badge>
                      </TableCell>
                      <TableCell className="text-sm">{decision.scenario}</TableCell>
                      <TableCell className="text-sm">{decision.duration}</TableCell>
                      <TableCell className="text-sm">
                        {decision.until ? new Date(decision.until).toLocaleString() : 'N/A'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <AlertCircle className="h-12 w-12 text-muted-foreground mb-4" />
              <p className="text-lg font-medium">No decisions found</p>
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
          <CardDescription>Understanding decision list filters</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>
            <strong>Time Filters:</strong> Use duration format like 4h (4 hours), 30d (30 days), 1w (1 week)
          </p>
          <p>
            <strong>Type:</strong> Filter by decision type (ban, captcha, throttle)
          </p>
          <p>
            <strong>Scope:</strong> Filter by scope (ip, range, session)
          </p>
          <p>
            <strong>Origin:</strong> Filter by source (cscli, crowdsec, console, lists, CAPI)
          </p>
          <p>
            <strong>Value:</strong> Specific value to match (IP address, username, etc.)
          </p>
          <p>
            <strong>Scenario:</strong> Filter by specific scenario (e.g., crowdsecurity/ssh-bf)
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
