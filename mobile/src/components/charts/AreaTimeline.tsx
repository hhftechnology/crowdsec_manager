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
  dataKey?: string
  xAxisKey?: string
  color?: string
  height?: number
}

interface ChartTooltipPayload {
  name: string
  value: number
}

interface ChartTooltipProps {
  active?: boolean
  payload?: ChartTooltipPayload[]
  label?: string
}

function ChartTooltip({ active, payload, label }: ChartTooltipProps) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-md border border-hairline bg-canvas px-sm py-xs text-caption">
      <p className="text-muted">{label}</p>
      {payload.map((entry) => (
        <p key={entry.name} className="font-medium text-ink">
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
  height = 200,
}: AreaTimelineProps) {
  const gradientId = `mobile-area-${dataKey}`
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -16 }}>
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.35} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--hairline))" vertical={false} />
        <XAxis
          dataKey={xAxisKey}
          tick={{ fontSize: 10, fill: 'hsl(var(--muted))' }}
          tickLine={false}
          axisLine={false}
        />
        <YAxis
          tick={{ fontSize: 10, fill: 'hsl(var(--muted))' }}
          tickLine={false}
          axisLine={false}
          allowDecimals={false}
          width={30}
        />
        <Tooltip content={<ChartTooltip />} />
        <Area
          type="monotone"
          dataKey={dataKey}
          stroke={color}
          strokeWidth={2}
          fill={`url(#${gradientId})`}
          fillOpacity={1}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}
