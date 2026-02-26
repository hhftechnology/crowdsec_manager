import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { CHART_COLORS } from '@/lib/chart-utils'

interface BarDistributionProps {
  data: { name: string; value: number }[]
  /** Bar orientation. Defaults to `"vertical"` (bars grow upward). */
  layout?: 'horizontal' | 'vertical'
  /** Bar fill color. Defaults to chart-1 (maroon). */
  color?: string
  /** Chart height in pixels. Defaults to 300. */
  height?: number
  /** Bar width in pixels. Defaults to 20. */
  barSize?: number
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

export default function BarDistribution({
  data,
  layout = 'vertical',
  color = CHART_COLORS[0],
  height = 300,
  barSize = 20,
}: BarDistributionProps) {
  // recharts "vertical" layout means bars are horizontal (categories on Y-axis).
  // Our prop semantics: "vertical" = bars grow upward, "horizontal" = bars grow rightward.
  const rechartsLayout = layout === 'horizontal' ? 'vertical' : 'horizontal'

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart
        data={data}
        layout={rechartsLayout}
        margin={{ top: 4, right: 4, bottom: 0, left: layout === 'horizontal' ? 40 : -12 }}
      >
        <CartesianGrid
          strokeDasharray="3 3"
          stroke="hsl(var(--border))"
          horizontal={layout === 'vertical'}
          vertical={layout === 'horizontal'}
        />

        {layout === 'vertical' ? (
          <>
            <XAxis
              dataKey="name"
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
          </>
        ) : (
          <>
            <XAxis
              type="number"
              tick={{ fontSize: 12, fill: 'hsl(var(--muted-foreground))' }}
              tickLine={false}
              axisLine={false}
              allowDecimals={false}
            />
            <YAxis
              type="category"
              dataKey="name"
              tick={{ fontSize: 12, fill: 'hsl(var(--muted-foreground))' }}
              tickLine={false}
              axisLine={false}
              width={80}
            />
          </>
        )}

        <Tooltip content={<ChartTooltip />} />

        <Bar
          dataKey="value"
          fill={color}
          barSize={barSize}
          radius={layout === 'vertical' ? [4, 4, 0, 0] : [0, 4, 4, 0]}
        />
      </BarChart>
    </ResponsiveContainer>
  )
}
