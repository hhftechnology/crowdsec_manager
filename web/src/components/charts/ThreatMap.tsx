import { useState, type MouseEvent } from 'react'
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
} from 'react-simple-maps'
import { Globe } from 'lucide-react'
import worldMapUrl from 'world-atlas/countries-110m.json?url'
import type { ThreatMapPoint } from '@/lib/threat-map'

interface ThreatMapProps {
  data: ThreatMapPoint[]
  /** Map height in pixels. Defaults to 400. */
  height?: number
  onMarkerClick?: (point: ThreatMapPoint) => void
  formatTooltip?: (point: ThreatMapPoint) => string
}

/** Scale marker radius based on value, clamped between 4 and 20 pixels. */
function markerRadius(value: number, maxValue: number): number {
  if (maxValue === 0) return 4
  const normalized = value / maxValue
  return Math.max(4, Math.min(20, 4 + normalized * 16))
}

function defaultTooltip(point: ThreatMapPoint): string {
  const label = point.label ?? point.country ?? `${point.lat.toFixed(1)}, ${point.lng.toFixed(1)}`
  return `${label}: ${point.value.toLocaleString()}`
}

export default function ThreatMap({
  data,
  height = 400,
  onMarkerClick,
  formatTooltip = defaultTooltip,
}: ThreatMapProps) {
  const [tooltip, setTooltip] = useState<{ x: number; y: number; content: string } | null>(null)

  if (data.length === 0) {
    return (
      <div
        className="flex flex-col items-center justify-center text-muted-foreground"
        style={{ height }}
      >
        <Globe className="mb-2 h-10 w-10 opacity-40" />
        <p className="text-sm">No geographic data available</p>
      </div>
    )
  }

  const maxValue = Math.max(...data.map((d) => d.value))

  return (
    <div className="relative" style={{ height }}>
      <ComposableMap
        projection="geoMercator"
        projectionConfig={{ scale: 120, center: [0, 30] }}
        width={800}
        height={height}
        style={{ width: '100%', height: '100%' }}
      >
        <Geographies geography={worldMapUrl}>
          {({ geographies }) =>
            geographies.map((geo) => (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                fill="hsl(var(--muted))"
                stroke="hsl(var(--border))"
                strokeWidth={0.5}
                style={{
                  default: { outline: 'none' },
                  hover: { outline: 'none', fill: 'hsl(var(--accent))' },
                  pressed: { outline: 'none' },
                }}
              />
            ))
          }
        </Geographies>

        {data.map((point, index) => (
          <Marker
            key={`marker-${index}`}
            coordinates={[point.lng, point.lat]}
            onMouseEnter={(e: MouseEvent<SVGGElement>) => {
              setTooltip({
                x: e.clientX,
                y: e.clientY,
                content: formatTooltip(point),
              })
            }}
            onMouseLeave={() => setTooltip(null)}
            onClick={() => onMarkerClick?.(point)}
          >
            <circle
              r={markerRadius(point.value, maxValue)}
              fill="hsl(var(--chart-1))"
              fillOpacity={0.7}
              stroke="hsl(var(--chart-1))"
              strokeWidth={1}
              strokeOpacity={0.3}
              style={{ cursor: onMarkerClick ? 'pointer' : 'default' }}
            />
          </Marker>
        ))}
      </ComposableMap>

      {tooltip && (
        <div
          className="pointer-events-none fixed z-50 rounded-lg border bg-popover px-3 py-2 text-sm text-popover-foreground shadow-lg"
          style={{ left: tooltip.x + 12, top: tooltip.y - 12 }}
        >
          {tooltip.content}
        </div>
      )}
    </div>
  )
}
