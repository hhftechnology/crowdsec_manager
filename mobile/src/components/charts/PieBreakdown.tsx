import {
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from 'recharts'
import { CHART_COLORS } from '@/lib/chart-utils'

interface PieBreakdownProps {
  data: { name: string; value: number }[]
  height?: number
  innerRadius?: number
  outerRadius?: number
  showLegend?: boolean
}

interface ChartTooltipPayload {
  name: string
  value: number
}

interface ChartTooltipProps {
  active?: boolean
  payload?: ChartTooltipPayload[]
}

function ChartTooltip({ active, payload }: ChartTooltipProps) {
  if (!active || !payload?.length) return null
  const entry = payload[0]
  return (
    <div className="rounded-md border border-hairline bg-canvas px-sm py-xs text-caption">
      <p className="font-medium text-ink">
        {entry.name}: {entry.value.toLocaleString()}
      </p>
    </div>
  )
}

export default function PieBreakdown({
  data,
  height = 220,
  innerRadius = 50,
  outerRadius = 80,
  showLegend = true,
}: PieBreakdownProps) {
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
          stroke="hsl(var(--canvas))"
        >
          {data.map((_, idx) => (
            <Cell key={`cell-${idx}`} fill={CHART_COLORS[idx % CHART_COLORS.length]} />
          ))}
        </Pie>
        <Tooltip content={<ChartTooltip />} />
        {showLegend && (
          <Legend
            verticalAlign="bottom"
            iconType="circle"
            iconSize={8}
            formatter={(value: string) => <span className="text-caption text-ink">{value}</span>}
          />
        )}
      </PieChart>
    </ResponsiveContainer>
  )
}
