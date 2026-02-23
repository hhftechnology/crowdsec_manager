/**
 * Chart utility functions for data processing and formatting.
 * Used by recharts and react-simple-maps chart components.
 */

/** Supported time bucket intervals for timeline charts. */
export type TimeInterval = '1h' | '6h' | '1d' | '7d'

/** Chart colors referencing CSS custom properties from the design system. */
export const CHART_COLORS = [
  'hsl(var(--chart-1))',
  'hsl(var(--chart-2))',
  'hsl(var(--chart-3))',
  'hsl(var(--chart-4))',
  'hsl(var(--chart-5))',
] as const

/** Named identifiers for chart color slots (useful for gradient IDs). */
export const CHART_FILL_IDS = [
  'chart-1',
  'chart-2',
  'chart-3',
  'chart-4',
  'chart-5',
] as const

/** Returns the number of milliseconds for a given time interval. */
function intervalToMs(interval: TimeInterval): number {
  switch (interval) {
    case '1h':
      return 5 * 60 * 1000 // 5-minute buckets
    case '6h':
      return 30 * 60 * 1000 // 30-minute buckets
    case '1d':
      return 60 * 60 * 1000 // 1-hour buckets
    case '7d':
      return 24 * 60 * 60 * 1000 // 1-day buckets
  }
}

/**
 * Bucket an array of records by a date field into fixed time intervals.
 * Returns an array of `{ date, count }` objects sorted chronologically.
 *
 * @param data - Source records
 * @param dateField - Key whose value is a date string or Date
 * @param interval - The span that determines bucket width
 */
export function bucketByTime<T>(
  data: T[],
  dateField: keyof T,
  interval: TimeInterval,
): { date: string; count: number }[] {
  if (data.length === 0) return []

  const bucketMs = intervalToMs(interval)

  // Determine the time range
  const timestamps = data.map((item) => new Date(item[dateField] as string | number | Date).getTime())
  const minTime = Math.min(...timestamps)
  const maxTime = Math.max(...timestamps)

  // Align bucket start to the interval boundary
  const bucketStart = Math.floor(minTime / bucketMs) * bucketMs
  const bucketEnd = Math.ceil(maxTime / bucketMs) * bucketMs

  // Initialize buckets
  const buckets = new Map<number, number>()
  for (let t = bucketStart; t <= bucketEnd; t += bucketMs) {
    buckets.set(t, 0)
  }

  // Fill buckets
  for (const ts of timestamps) {
    const key = Math.floor(ts / bucketMs) * bucketMs
    buckets.set(key, (buckets.get(key) ?? 0) + 1)
  }

  // Convert to sorted array
  return Array.from(buckets.entries())
    .sort(([a], [b]) => a - b)
    .map(([ts, count]) => ({
      date: new Date(ts).toISOString(),
      count,
    }))
}

/**
 * Group records by the value of a field, count occurrences, sort descending,
 * and optionally limit the number of results. Remaining items are folded
 * into an "Other" entry when a limit is applied.
 *
 * @param data - Source records
 * @param field - Key to group by
 * @param limit - Max number of groups to return (excess grouped as "Other")
 */
export function groupByField<T>(
  data: T[],
  field: keyof T,
  limit?: number,
): { name: string; value: number }[] {
  const counts = new Map<string, number>()

  for (const item of data) {
    const key = String(item[field] ?? 'Unknown')
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }

  const sorted = Array.from(counts.entries())
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)

  if (limit === undefined || sorted.length <= limit) {
    return sorted
  }

  const top = sorted.slice(0, limit)
  const otherValue = sorted.slice(limit).reduce((sum, item) => sum + item.value, 0)

  if (otherValue > 0) {
    top.push({ name: 'Other', value: otherValue })
  }

  return top
}

/**
 * Format a date string for chart axis labels, adapting to the time interval.
 *
 * - `1h`  -> "14:00"
 * - `6h`  -> "Mon 14:00"
 * - `1d`  -> "Jan 15"
 * - `7d`  -> "Jan 15"
 */
export function formatChartDate(date: string | Date, interval: TimeInterval): string {
  const d = new Date(date)

  switch (interval) {
    case '1h':
      return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
    case '6h':
      return `${d.toLocaleDateString(undefined, { weekday: 'short' })} ${d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}`
    case '1d':
    case '7d':
      return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
  }
}
