import { useQuery } from '@tanstack/react-query'
import { crowdsecAPI } from '@/lib/api/crowdsec'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { RefreshCw, BarChart3, Activity, Shield, Eye, Database, Server, FileText } from 'lucide-react'
import { PageHeader, PageLoader, QueryError } from '@/components/common'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Tabs, TabsContent, TabsList, TabsTrigger,
} from '@/components/ui/tabs'

// Metrics data returned by `cscli metrics -o json`
type MetricsData = Record<string, unknown>

/** Flatten a nested metrics section into displayable rows */
function flattenMetricsSection(section: unknown): { key: string; values: Record<string, string | number> }[] {
  if (!section || typeof section !== 'object') return []
  const rows: { key: string; values: Record<string, string | number> }[] = []
  for (const [key, val] of Object.entries(section as Record<string, unknown>)) {
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      // Could be a simple {hits: 10, parsed: 10} or nested further
      const flat = flattenToKV(val as Record<string, unknown>)
      rows.push({ key, values: flat })
    } else {
      rows.push({ key, values: { value: String(val ?? '') } })
    }
  }
  return rows
}

/** Recursively flatten nested objects into dot-separated keys */
function flattenToKV(obj: Record<string, unknown>, prefix = ''): Record<string, string | number> {
  const result: Record<string, string | number> = {}
  for (const [k, v] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${k}` : k
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      Object.assign(result, flattenToKV(v as Record<string, unknown>, fullKey))
    } else if (typeof v === 'number') {
      result[fullKey] = v
    } else {
      result[fullKey] = String(v ?? '')
    }
  }
  return result
}

/** Collect all unique value-column names from a set of rows */
function collectColumns(rows: { values: Record<string, string | number> }[]): string[] {
  const cols = new Set<string>()
  for (const row of rows) {
    for (const k of Object.keys(row.values)) cols.add(k)
  }
  return Array.from(cols).sort()
}

function formatNumber(v: string | number): string {
  if (typeof v === 'number') return v.toLocaleString()
  return v
}

const SECTION_META: Record<string, { label: string; icon: React.ReactNode }> = {
  acquisition: { label: 'Acquisition', icon: <FileText className="h-4 w-4" /> },
  parsers: { label: 'Parsers', icon: <Database className="h-4 w-4" /> },
  scenarios: { label: 'Scenarios', icon: <Activity className="h-4 w-4" /> },
  bouncers: { label: 'Bouncers', icon: <Shield className="h-4 w-4" /> },
  decisions: { label: 'Decisions', icon: <Shield className="h-4 w-4" /> },
  alerts: { label: 'Alerts', icon: <Activity className="h-4 w-4" /> },
  lapi: { label: 'LAPI', icon: <Server className="h-4 w-4" /> },
  'lapi-bouncer': { label: 'LAPI Bouncer', icon: <Server className="h-4 w-4" /> },
  'lapi-machine': { label: 'LAPI Machine', icon: <Server className="h-4 w-4" /> },
  'lapi-decisions': { label: 'LAPI Decisions', icon: <Server className="h-4 w-4" /> },
  whitelists: { label: 'Whitelists', icon: <Eye className="h-4 w-4" /> },
  'appsec-engine': { label: 'AppSec Engine', icon: <Shield className="h-4 w-4" /> },
  'appsec-rule': { label: 'AppSec Rules', icon: <Shield className="h-4 w-4" /> },
  stash: { label: 'Stash', icon: <Database className="h-4 w-4" /> },
}

/** Render a single metrics section as a table */
function MetricsSection({ name, data }: { name: string; data: unknown }) {
  const rows = flattenMetricsSection(data)
  if (rows.length === 0) return null
  const columns = collectColumns(rows)

  const meta = SECTION_META[name] ?? { label: name, icon: <BarChart3 className="h-4 w-4" /> }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          {meta.icon}
          {meta.label}
          <Badge variant="secondary" className="text-xs font-normal">{rows.length}</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="rounded-md border overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="min-w-[200px]">Name</TableHead>
                {columns.map(col => (
                  <TableHead key={col} className="text-right whitespace-nowrap">{col}</TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map(row => (
                <TableRow key={row.key}>
                  <TableCell className="font-mono text-sm">{row.key}</TableCell>
                  {columns.map(col => (
                    <TableCell key={col} className="text-right font-mono text-sm tabular-nums">
                      {row.values[col] !== undefined ? formatNumber(row.values[col]) : '-'}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  )
}

// Preferred ordering of tabs
const SECTION_ORDER = [
  'acquisition', 'parsers', 'scenarios', 'bouncers', 'decisions',
  'alerts', 'lapi', 'lapi-bouncer', 'lapi-machine', 'lapi-decisions',
  'whitelists', 'appsec-engine', 'appsec-rule', 'stash',
]

export default function Metrics() {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['crowdsec-metrics'],
    queryFn: async () => {
      const response = await crowdsecAPI.getMetrics()
      return (response.data.data ?? null) as MetricsData | null
    },
    refetchInterval: 30000,
  })

  // Sort sections: known order first, then any extras
  const sections = data
    ? Object.keys(data).sort((a, b) => {
        const ai = SECTION_ORDER.indexOf(a)
        const bi = SECTION_ORDER.indexOf(b)
        if (ai === -1 && bi === -1) return a.localeCompare(b)
        if (ai === -1) return 1
        if (bi === -1) return -1
        return ai - bi
      })
    : []

  // Filter out empty sections
  const nonEmptySections = sections.filter(s => {
    const val = data![s]
    if (!val || typeof val !== 'object') return false
    return Object.keys(val as Record<string, unknown>).length > 0
  })

  return (
    <div className="space-y-6">
      <PageHeader
        title="CrowdSec Metrics"
        description="Real-time metrics from the CrowdSec engine"
      />

      {isError && <QueryError error={error} onRetry={refetch} />}

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5" />
              <div>
                <CardTitle>Engine Metrics</CardTitle>
                <CardDescription>
                  CrowdSec LAPI metrics output
                </CardDescription>
              </div>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetch()}
              disabled={isLoading}
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <PageLoader message="Loading metrics..." />
          ) : nonEmptySections.length > 0 ? (
            <Tabs defaultValue={nonEmptySections[0]} className="space-y-4">
              <TabsList className="flex-wrap h-auto gap-1">
                {nonEmptySections.map(section => {
                  const meta = SECTION_META[section] ?? { label: section }
                  return (
                    <TabsTrigger key={section} value={section} className="text-xs">
                      {meta.label}
                    </TabsTrigger>
                  )
                })}
              </TabsList>
              {nonEmptySections.map(section => (
                <TabsContent key={section} value={section}>
                  <MetricsSection name={section} data={data![section]} />
                </TabsContent>
              ))}
            </Tabs>
          ) : (
            <p className="text-muted-foreground text-sm">No metrics data available</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
