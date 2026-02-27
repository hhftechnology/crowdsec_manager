import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { CHART_COLORS } from '@/lib/chart-utils'

interface AreaTimelineProps {
  data: { date: string; value: number; [key: string]: string | number }[]
  /** Data key for the Y-axis value. Defaults to `"value"`. */
  dataKey?: string
  /** Data key for the X-axis. Defaults to `"date"`. */
  xAxisKey?: string
  /** Line and fill color. Defaults to chart-1 (maroon). */
  color?: string
  /** Chart height in pixels. Defaults to 300. */
  height?: number
  /** Show dashed grid lines. */
  showGrid?: boolean
  /** Fill area with a gradient. Defaults to true. */
  gradientFill?: boolean
}

interface ChartTooltipPayload {
  name: string
  value: number
  color?: string
}

interface ChartTooltipProps {
  active?: boolean
  payload?: ChartTooltipPayload[]
  label?: string
}

function ChartTooltip({ active, payload, label }: ChartTooltipProps) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border bg-popover p-3 text-popover-foreground shadow-lg">
      <p className="mb-1 text-xs text-muted-foreground">{label}</p>
      {payload.map((entry) => (
        <p key={entry.name} className="text-sm font-medium">
          {entry.name}: {entry.value.toLocaleString()}
        </p>
      ))}
    </div>
  )
}

export default function AreaTimeline({
  data,
  dataKey = 'value',
  xAxisKey = 'date',
  color = CHART_COLORS[0],
  height = 300,
  showGrid = true,
  gradientFill = true,
}: AreaTimelineProps) {
  const gradientId = `area-gradient-${dataKey}`

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -12 }}>
        <defs>
          {gradientFill && (
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.3} />
              <stop offset="100%" stopColor={color} stopOpacity={0} />
            </linearGradient>
          )}
        </defs>

        {showGrid && (
          <CartesianGrid
            strokeDasharray="3 3"
            stroke="hsl(var(--border))"
            vertical={false}
          />
        )}

        <XAxis
          dataKey={xAxisKey}
          tick={{ fontSize: 12, fill: 'hsl(var(--muted-foreground))' }}
          tickLine={false}
          axisLine={false}
        />
        <YAxis
          tick={{ fontSize: 12, fill: 'hsl(var(--muted-foreground))' }}
          tickLine={false}
          axisLine={false}
          allowDecimals={false}
        />

        <Tooltip content={<ChartTooltip />} />

        <Area
          type="monotone"
          dataKey={dataKey}
          stroke={color}
          strokeWidth={2}
          fill={gradientFill ? `url(#${gradientId})` : color}
          fillOpacity={gradientFill ? 1 : 0.1}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}
