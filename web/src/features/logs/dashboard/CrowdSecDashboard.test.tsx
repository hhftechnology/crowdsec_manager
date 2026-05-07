import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

import { CrowdSecDashboard } from './CrowdSecDashboard'

afterEach(() => cleanup())
import type { CrowdSecDashboard as CrowdSecDashboardData } from '@/lib/api/dashboard'

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

const sample: CrowdSecDashboardData = {
  range: '1h',
  generated_at: '2026-05-07T12:00:00Z',
  total_events: 50,
  decisions: 10,
  alerts: 8,
  parser_errors: 2,
  series: [],
  top_scenarios: [{ name: 'crowdsecurity/http-probing', value: 5 }],
  top_source_ips: [{ ip: '1.2.3.4', count: 3 }],
  top_origins: [{ name: 'crowdsec', value: 7 }],
  top_decision_types: [{ name: 'ban', value: 5 }],
  acquisition: [{ source: 'file:/var/log/auth.log', lines: 12 }],
  bouncer_activity: [],
  recent_errors: [],
}

describe('CrowdSecDashboard', () => {
  it('renders four KPI tiles', () => {
    render(<CrowdSecDashboard data={sample} />)
    const titles = screen.getAllByTestId('stat-card').map((c) => c.getAttribute('data-title'))
    expect(titles).toEqual(expect.arrayContaining(['Total Events', 'Decisions', 'Alerts', 'Parser Errors']))
  })

  it('renders scenario / origin / decision-type widgets', () => {
    render(<CrowdSecDashboard data={sample} />)
    const titles = screen.getAllByTestId('chart-card').map((c) => c.getAttribute('data-title'))
    expect(titles).toEqual(expect.arrayContaining(['Top Scenarios', 'Decision Types', 'Top Origins', 'Acquisition']))
  })
})
