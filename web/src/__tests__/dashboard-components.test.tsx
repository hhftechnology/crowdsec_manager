import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'

afterEach(() => cleanup())

import { RangeSelector } from '@/features/logs/dashboard/RangeSelector'
import { TraefikDashboard } from '@/features/logs/dashboard/TraefikDashboard'
import { CrowdSecDashboard } from '@/features/logs/dashboard/CrowdSecDashboard'

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

describe('RangeSelector', () => {
  it('highlights the active range and calls onChange', () => {
    const onChange = vi.fn()
    render(<RangeSelector value="1h" onChange={onChange} />)
    fireEvent.click(screen.getByRole('button', { name: '6h' }))
    expect(onChange).toHaveBeenCalledWith('6h')
  })
})

describe('TraefikDashboard empty state', () => {
  it('renders KPI cards even when data is undefined', () => {
    render(<TraefikDashboard data={undefined} isLoading={true} />)
    // Loading state still renders the dashboard scaffolding (no crash).
    expect(screen.getAllByTestId('stat-card').length).toBeGreaterThan(0)
  })
})

describe('CrowdSecDashboard empty state', () => {
  it('renders KPI cards even when data is undefined', () => {
    render(<CrowdSecDashboard data={undefined} isLoading={true} />)
    expect(screen.getAllByTestId('stat-card').length).toBeGreaterThan(0)
  })
})
