import { describe, expect, it } from 'vitest'
import { parseTraefikLog } from '@/lib/utils'

describe('parseTraefikLog', () => {
  it('normalizes Traefik JSON durations from nanoseconds to milliseconds', () => {
    const parsed = parseTraefikLog('{"Duration":12000000,"RequestMethod":"GET","RequestPath":"/health","DownstreamStatus":200}')

    expect(parsed.duration).toBe(12)
    expect(parsed.Duration).toBe(12)
  })
})
