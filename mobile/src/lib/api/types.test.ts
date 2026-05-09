import { describe, expect, it } from 'vitest'
import { DASHBOARD_RANGES } from './types'

describe('mobile api types', () => {
  it('exposes the supported dashboard ranges', () => {
    expect(DASHBOARD_RANGES).toEqual(['5m', '1h', '6h', '24h'])
  })
})
