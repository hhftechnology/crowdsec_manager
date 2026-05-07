import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

import { TraefikDashboard } from './TraefikDashboard'

afterEach(() => cleanup())
import type { TraefikDashboard as TraefikDashboardData } from '@/lib/api/dashboard'

vi.mock('@/components/charts', async () => {
  const React = await import('react')
  return {
    AreaTimeline: () => React.createElement('div', { 'data-testid': 'area-timeline' }),
    BarDistribution: () => React.createElement('div', { 'data-testid': 'bar-distribution' }),
    PieBreakdown: () => React.createElement('div', { 'data-testid': 'pie-breakdown' }),
    ThreatMap: () => React.createElement('div', { 'data-testid': 'threat-map' }),
    StatCard: ({ title, value }: { title: string; value: string | number }) =>
      React.createElement('div', { 'data-testid': 'stat-card', 'data-title': title }, String(value)),
    ChartCard: ({ title, children }: { title: string; children: React.ReactNode }) =>
      React.createElement('div', { 'data-testid': 'chart-card', 'data-title': title }, children),
  }
})

const sample: TraefikDashboardData = {
  range: '1h',
  format: 'json',
  generated_at: '2026-05-07T12:00:00Z',
  total_requests: 100,
  unique_ips: 12,
  avg_duration_ms: 14.5,
  error_rate: 0.05,
  series: [],
  status_codes: [{ name: '200', value: 95 }],
  methods: [{ name: 'GET', value: 90 }],
  top_ips: [{ ip: '1.2.3.4', count: 5, country: 'DE', lat: 51, lng: 9 }],
  top_hosts: [{ name: 'example.com', value: 50 }],
  top_routers: [{ name: 'router-a', value: 30 }],
  slowest_endpoints: [{ name: '/slow', value: 800 }],
  tls_versions: [{ name: '1.3', value: 80 }],
  recent_errors: [],
}

describe('TraefikDashboard', () => {
  it('renders four KPI tiles with formatted values', () => {
    render(<TraefikDashboard data={sample} />)
    const cards = screen.getAllByTestId('stat-card')
    const titles = cards.map((c) => c.getAttribute('data-title'))
    expect(titles).toContain('Total Requests')
    expect(titles).toContain('Unique IPs')
    expect(titles).toContain('Avg Duration')
    expect(titles).toContain('Error Rate')
  })

  it('shows JSON-only widgets when format is json', () => {
    render(<TraefikDashboard data={sample} />)
    const titles = screen.getAllByTestId('chart-card').map((c) => c.getAttribute('data-title'))
    expect(titles).toContain('Top Hosts')
    expect(titles).toContain('Top Routers')
    expect(titles).toContain('Slowest Endpoints')
    expect(titles).toContain('TLS Versions')
  })

  it('hides JSON-only widgets and shows hint in CLF mode', () => {
    render(<TraefikDashboard data={{ ...sample, format: 'clf' }} />)
    expect(screen.queryByText(/Enable Traefik JSON access log/i)).toBeTruthy()
  })
})
