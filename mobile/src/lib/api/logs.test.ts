import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApi } from '@/lib/api'
import type { ConnectionProfile } from '@/lib/connection'

function profile(): ConnectionProfile {
  return {
    mode: 'direct',
    baseUrl: 'https://api.example.com',
    allowInsecure: false,
    proxyUsername: '',
    proxyPassword: '',
    pangolinToken: '',
    pangolinTokenParam: 'p_token',
  }
}

describe('logs API dashboard endpoints', () => {
  const api = createApi(profile())

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('hits the Traefik dashboard endpoint with the chosen range', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          success: true,
          data: {
            range: '1h',
            format: 'clf',
            generated_at: '2026-05-07T12:00:00Z',
            total_requests: 0,
            unique_ips: 0,
            avg_duration_ms: null,
            error_rate: 0,
            series: [],
            status_codes: [],
            methods: [],
            top_ips: [],
            top_hosts: [],
            top_routers: [],
            slowest_endpoints: [],
            tls_versions: [],
            recent_errors: [],
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )

    await api.logs.dashboardTraefik('1h')

    const url = fetchSpy.mock.calls[0][0] as string
    expect(url).toContain('/api/logs/traefik/dashboard')
    expect(url).toContain('range=1h')
  })

  it('hits the CrowdSec dashboard endpoint', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          success: true,
          data: {
            range: '6h',
            generated_at: '2026-05-07T12:00:00Z',
            total_events: 0,
            decisions: 0,
            alerts: 0,
            parser_errors: 0,
            series: [],
            top_scenarios: [],
            top_source_ips: [],
            top_origins: [],
            top_decision_types: [],
            acquisition: [],
            bouncer_activity: [],
            recent_errors: [],
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )

    await api.logs.dashboardCrowdSec('6h')

    const url = fetchSpy.mock.calls[0][0] as string
    expect(url).toContain('/api/logs/crowdsec/dashboard')
    expect(url).toContain('range=6h')
  })
})
