import { describe, expect, it } from 'vitest'
import { parseTraefikLog } from '@/lib/utils'

describe('parseTraefikLog', () => {
  it('normalizes Traefik JSON durations from nanoseconds to milliseconds', () => {
    const parsed = parseTraefikLog('{"Duration":12000000,"RequestMethod":"GET","RequestPath":"/health","DownstreamStatus":200}')

    expect(parsed.duration).toBe(12)
    expect(parsed.Duration).toBe(12)
  })

  it('normalizes CLF timestamps to ISO strings', () => {
    const parsed = parseTraefikLog('1.2.3.4 - - [07/May/2026:11:55:00 +0000] "GET /health HTTP/1.1" 200 100')

    expect(parsed.t).toBe('2026-05-07T11:55:00.000Z')
    expect(Number.isNaN(new Date(parsed.t as string).getTime())).toBe(false)
  })
})
