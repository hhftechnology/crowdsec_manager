import type { CrowdSecAlert } from '@/lib/api'

export interface ThreatMapPoint {
  lat: number
  lng: number
  value: number
  country?: string
  label?: string
}

function isValidCoordinate(value: number | undefined): value is number {
  return typeof value === 'number' && Number.isFinite(value)
}

export function buildThreatMapPoints(alerts: CrowdSecAlert[]): ThreatMapPoint[] {
  const buckets = new Map<string, ThreatMapPoint>()

  for (const alert of alerts) {
    const lat = alert.source?.latitude
    const lng = alert.source?.longitude

    if (!isValidCoordinate(lat) || !isValidCoordinate(lng)) {
      continue
    }

    const country = alert.source?.cn?.trim() || undefined
    const label = country ?? (alert.source?.as_name?.trim() || alert.value)
    const key = `${country ?? 'unknown'}:${lat}:${lng}`
    const existing = buckets.get(key)

    if (existing) {
      existing.value += 1
      continue
    }

    buckets.set(key, {
      lat,
      lng,
      value: 1,
      country,
      label,
    })
  }

  return Array.from(buckets.values()).sort((a, b) => b.value - a.value)
}
