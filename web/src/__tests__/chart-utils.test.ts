import { describe, expect, it } from 'vitest'

import { bucketByUtcDay } from '@/lib/chart-utils'

describe('bucketByUtcDay', () => {
  it('returns daily chart points from oldest to newest', () => {
    const points = bucketByUtcDay([
      { created_at: '2026-05-06T10:00:00Z' },
      { created_at: '2026-05-04T10:00:00Z' },
      { created_at: '2026-05-05T10:00:00Z' },
      { created_at: '2026-05-06T11:00:00Z' },
    ], 'created_at')

    expect(points.map((point) => point.ts)).toEqual([
      '2026-05-04T00:00:00.000Z',
      '2026-05-05T00:00:00.000Z',
      '2026-05-06T00:00:00.000Z',
    ])
    expect(points.map((point) => point.value)).toEqual([1, 1, 2])
  })
})
