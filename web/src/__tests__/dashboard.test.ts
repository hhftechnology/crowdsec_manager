import { describe, expect, it } from 'vitest'

import { DASHBOARD_RANGES, type DashboardRange, dashboardAPI } from '@/lib/api/dashboard'

describe('dashboard API client', () => {
  it('exposes the four supported time ranges', () => {
    const expected: DashboardRange[] = ['5m', '1h', '6h', '24h']
    expect(DASHBOARD_RANGES).toEqual(expected)
  })

  it('exposes Traefik and CrowdSec endpoints', () => {
    expect(typeof dashboardAPI.getTraefik).toBe('function')
    expect(typeof dashboardAPI.getCrowdSec).toBe('function')
  })
})
