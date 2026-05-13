import { useState, useEffect, useRef, type MouseEvent } from 'react'
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  ZoomableGroup
} from 'react-simple-maps'
import { Globe, Plus, Minus, Maximize } from 'lucide-react'
import worldMapUrl from 'world-atlas/countries-110m.json?url'
import type { ThreatMapPoint } from '@/lib/threat-map'
import { Button } from '@/components/ui/button'

interface ThreatMapProps {
  data: ThreatMapPoint[]
  /** Map height in pixels. Defaults to 400. */
  height?: number
  onMarkerClick?: (point: ThreatMapPoint) => void
  formatTooltip?: (point: ThreatMapPoint) => string
}

/** Scale marker radius based on value, clamped between 4 and 20 pixels. */
function markerRadius(value: number, maxValue: number, zoom: number): number {
  if (maxValue === 0) return 4
  const normalized = value / maxValue
  // Scale down markers as we zoom in so they don't cover the whole map
  const baseRadius = Math.max(4, Math.min(20, 4 + normalized * 16))
  return baseRadius / Math.sqrt(zoom)
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
  const [position, setPosition] = useState({ coordinates: [0, 20] as [number, number], zoom: 1 })
  const containerRef = useRef<HTMLDivElement>(null)

  // Block page scrolling when mouse is over the map to allow
  // smooth zooming and panning without moving the page.
  useEffect(() => {
    const el = containerRef.current
    if (!el) return

    const handleWheel = (e: WheelEvent) => {
      e.preventDefault()
    }

    el.addEventListener('wheel', handleWheel, { passive: false })
    return () => el.removeEventListener('wheel', handleWheel)
  }, [])

  const handleZoomIn = () => {
    if (position.zoom >= 8) return
    setPosition((pos) => ({ ...pos, zoom: pos.zoom * 1.5 }))
  }

  const handleZoomOut = () => {
    if (position.zoom <= 1) return
    setPosition((pos) => ({ ...pos, zoom: Math.max(1, pos.zoom / 1.5) }))
  }

  const handleReset = () => {
    setPosition({ coordinates: [0, 20], zoom: 1 })
  }

  const handleMoveEnd = (newPosition: { coordinates: [number, number]; zoom: number }) => {
    setPosition(newPosition)
  }

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
    <div ref={containerRef} className="relative group overflow-hidden rounded-lg border bg-card" style={{ height }}>
      <div className="absolute right-3 top-3 z-10 flex flex-col gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
        <Button size="icon" variant="secondary" className="h-8 w-8 shadow-sm" onClick={handleZoomIn} title="Zoom In">
          <Plus className="h-4 w-4" />
        </Button>
        <Button size="icon" variant="secondary" className="h-8 w-8 shadow-sm" onClick={handleZoomOut} title="Zoom Out">
          <Minus className="h-4 w-4" />
        </Button>
        <Button size="icon" variant="secondary" className="h-8 w-8 shadow-sm" onClick={handleReset} title="Reset View">
          <Maximize className="h-4 w-4" />
        </Button>
      </div>

      <ComposableMap
        projection="geoMercator"
        width={800}
        height={height}
        style={{ width: '100%', height: '100%' }}
      >
        <ZoomableGroup
          zoom={position.zoom}
          center={position.coordinates}
          onMoveEnd={handleMoveEnd}
        >
          <Geographies geography={worldMapUrl}>
            {({ geographies }) =>
              geographies.map((geo) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill="hsl(var(--muted))"
                  stroke="hsl(var(--border))"
                  strokeWidth={0.5 / position.zoom}
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
                r={markerRadius(point.value, maxValue, position.zoom)}
                fill="hsl(var(--chart-1))"
                fillOpacity={0.6}
                stroke="hsl(var(--chart-1))"
                strokeWidth={1 / position.zoom}
                strokeOpacity={0.5}
                className="transition-all duration-300"
                style={{ cursor: onMarkerClick ? 'pointer' : 'default' }}
              />
            </Marker>
          ))}
        </ZoomableGroup>
      </ComposableMap>

      {tooltip && (
        <div
          className="pointer-events-none fixed z-50 rounded-lg border bg-popover px-3 py-2 text-xs font-medium text-popover-foreground shadow-xl backdrop-blur-sm"
          style={{ left: tooltip.x + 12, top: tooltip.y - 12 }}
        >
          {tooltip.content}
        </div>
      )}
    </div>
  )
}
