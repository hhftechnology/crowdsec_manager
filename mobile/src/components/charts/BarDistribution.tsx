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
  layout?: 'horizontal' | 'vertical'
  color?: string
  height?: number
  barSize?: number
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

export default function BarDistribution({
  data,
  layout = 'vertical',
  color = CHART_COLORS[0],
  height = 220,
  barSize = 16,
}: BarDistributionProps) {
  const rechartsLayout = layout === 'horizontal' ? 'vertical' : 'horizontal'
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart
        data={data}
        layout={rechartsLayout}
        margin={{ top: 4, right: 4, bottom: 0, left: layout === 'horizontal' ? 16 : -16 }}
      >
        <CartesianGrid
          strokeDasharray="3 3"
          stroke="hsl(var(--hairline))"
          horizontal={layout === 'vertical'}
          vertical={layout === 'horizontal'}
        />
        {layout === 'vertical' ? (
          <>
            <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'hsl(var(--muted))' }} tickLine={false} axisLine={false} />
            <YAxis tick={{ fontSize: 10, fill: 'hsl(var(--muted))' }} tickLine={false} axisLine={false} allowDecimals={false} width={30} />
          </>
        ) : (
          <>
            <XAxis type="number" tick={{ fontSize: 10, fill: 'hsl(var(--muted))' }} tickLine={false} axisLine={false} allowDecimals={false} />
            <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: 'hsl(var(--muted))' }} tickLine={false} axisLine={false} width={80} />
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
