import {
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from 'recharts'
import type { PieLabelRenderProps } from 'recharts'
import { CHART_COLORS } from '@/lib/chart-utils'

interface PieBreakdownProps {
  data: { name: string; value: number }[]
  /** Chart height in pixels. Defaults to 300. */
  height?: number
  /** Inner radius for donut hole. Defaults to 60. */
  innerRadius?: number
  /** Outer radius of the pie. Defaults to 100. */
  outerRadius?: number
  /** Show percentage labels on segments. */
  showLabels?: boolean
  /** Show legend below the chart. Defaults to true. */
  showLegend?: boolean
}

interface ChartTooltipPayload {
  name: string
  value: number
  color?: string
}

interface ChartTooltipProps {
  active?: boolean
  payload?: ChartTooltipPayload[]
}

function ChartTooltip({ active, payload }: ChartTooltipProps) {
  if (!active || !payload?.length) return null
  const entry = payload[0]
  return (
    <div className="rounded-lg border bg-popover p-3 text-popover-foreground shadow-lg">
      <p className="text-sm font-medium">
        {entry.name}: {entry.value.toLocaleString()}
      </p>
    </div>
  )
}

function renderLabel(props: PieLabelRenderProps) {
  const { cx, cy, midAngle, innerRadius, outerRadius, percent } = props
  if (
    typeof cx !== 'number' ||
    typeof cy !== 'number' ||
    typeof midAngle !== 'number' ||
    typeof innerRadius !== 'number' ||
    typeof outerRadius !== 'number' ||
    typeof percent !== 'number' ||
    percent < 0.05
  ) {
    return null
  }
  const RADIAN = Math.PI / 180
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5
  const x = cx + radius * Math.cos(-midAngle * RADIAN)
  const y = cy + radius * Math.sin(-midAngle * RADIAN)
  return (
    <text
      x={x}
      y={y}
      fill="hsl(var(--popover-foreground))"
      textAnchor="middle"
      dominantBaseline="central"
      fontSize={12}
      fontWeight={500}
    >
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  )
}

export default function PieBreakdown({
  data,
  height = 300,
  innerRadius = 60,
  outerRadius = 100,
  showLabels = false,
  showLegend = true,
}: PieBreakdownProps) {
  const total = data.reduce((sum, d) => sum + d.value, 0)

  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={innerRadius}
          outerRadius={outerRadius}
          dataKey="value"
          nameKey="name"
          strokeWidth={2}
          stroke="hsl(var(--background))"
          label={showLabels ? renderLabel : undefined}
          labelLine={false}
        >
          {data.map((_entry, index) => (
            <Cell
              key={`cell-${index}`}
              fill={CHART_COLORS[index % CHART_COLORS.length]}
            />
          ))}
        </Pie>

        {/* Center label showing total */}
        <text
          x="50%"
          y="50%"
          textAnchor="middle"
          dominantBaseline="central"
        >
          <tspan
            x="50%"
            dy="-0.3em"
            fontSize={20}
            fontWeight={700}
            fill="hsl(var(--foreground))"
          >
            {total.toLocaleString()}
          </tspan>
          <tspan
            x="50%"
            dy="1.4em"
            fontSize={12}
            fill="hsl(var(--muted-foreground))"
          >
            Total
          </tspan>
        </text>

        <Tooltip content={<ChartTooltip />} />

        {showLegend && (
          <Legend
            verticalAlign="bottom"
            iconType="circle"
            iconSize={8}
            formatter={(value: string) => (
              <span className="text-xs text-foreground">{value}</span>
            )}
          />
        )}
      </PieChart>
    </ResponsiveContainer>
  )
}
