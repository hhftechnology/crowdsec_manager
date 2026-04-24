import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import Dashboard from '@/pages/Dashboard'
import type { HistoryActivityResponse } from '@/lib/api/types'

const mockNavigate = vi.fn()

const mockApi = vi.hoisted(() => ({
  health: {
    checkStack: vi.fn(),
  },
  crowdsec: {
    getDecisionsSummary: vi.fn(),
    getDecisions: vi.fn(),
    getBouncers: vi.fn(),
    getAlertsAnalysis: vi.fn(),
    getHistoryActivity: vi.fn(),
  },
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

vi.mock('@/lib/api', () => ({
  default: mockApi,
}))

vi.mock('@/components/charts', () => ({
  StatCard: ({ title, value, description, loading }: { title: string; value: string | number; description?: string; loading?: boolean }) => (
    <section aria-label={title}>
      <span>{title}</span>
      {loading ? <span>Loading</span> : <strong>{value}</strong>}
      {description ? <small>{description}</small> : null}
    </section>
  ),
  ChartCard: ({ title, action, children }: { title: string; action?: React.ReactNode; children: React.ReactNode }) => (
    <section aria-label={title}>
      <h2>{title}</h2>
      {action}
      {children}
    </section>
  ),
  AreaTimeline: () => <div />,
  PieBreakdown: () => <div />,
  BarDistribution: () => <div />,
  ThreatMap: () => <div />,
}))

vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  BarChart: ({ data, children }: { data: Array<{ alerts: number; decisions: number }>; children: React.ReactNode }) => (
    <div data-testid="activity-chart">
      {data.map((item, index) => (
        <div data-testid="activity-bar" key={index}>
          {item.alerts}:{item.decisions}
        </div>
      ))}
      {children}
    </div>
  ),
  CartesianGrid: () => null,
  XAxis: () => null,
  YAxis: () => null,
  Tooltip: () => null,
  Legend: () => null,
  Bar: () => null,
}))

describe('Dashboard', () => {
  afterEach(() => {
    cleanup()
  })

  beforeEach(() => {
    vi.clearAllMocks()

    mockApi.health.checkStack.mockResolvedValue({
      data: { data: { containers: [], allRunning: true, timestamp: '2026-04-24T00:00:00Z' } },
    })
    mockApi.crowdsec.getDecisionsSummary.mockResolvedValue({
      data: { data: { count: 42, types: {}, scenarios: {} } },
    })
    mockApi.crowdsec.getDecisions.mockResolvedValue({
      data: { data: { decisions: [], count: 0 } },
    })
    mockApi.crowdsec.getBouncers.mockResolvedValue({
      data: { data: { bouncers: [], count: 0 } },
    })
    mockApi.crowdsec.getAlertsAnalysis.mockResolvedValue({
      data: { data: { alerts: [], count: 0 } },
    })
    mockApi.crowdsec.getHistoryActivity.mockImplementation(({ window, bucket }: { window: '24h' | '7d'; bucket: 'hour' | 'day' }) =>
      Promise.resolve({ data: { data: makeHistoryActivity(window, bucket) } }),
    )
  })

  it('renders activity bars from history activity and uses the summary count for active decisions', async () => {
    renderDashboard()

    await waitFor(() => {
      expect(mockApi.crowdsec.getHistoryActivity).toHaveBeenCalledWith({ window: '7d', bucket: 'day' })
    })

    expect(await screen.findByText('42')).toBeInTheDocument()
    await waitFor(() => {
      expect(within(screen.getByLabelText('Alerts (7d)')).getByText('2')).toBeInTheDocument()
    })
    expect(screen.getAllByTestId('activity-bar')).toHaveLength(7)
    expect(mockApi.crowdsec.getDecisions).toHaveBeenCalled()
  })

  it('renders the alert count and activity chart while detailed alert analysis is still loading', async () => {
    mockApi.crowdsec.getAlertsAnalysis.mockReturnValue(new Promise(() => undefined))

    renderDashboard()

    await waitFor(() => {
      expect(mockApi.crowdsec.getHistoryActivity).toHaveBeenCalledWith({ window: '7d', bucket: 'day' })
    })

    await waitFor(() => {
      expect(within(screen.getByLabelText('Alerts (7d)')).getByText('2')).toBeInTheDocument()
    })
    expect(screen.getAllByTestId('activity-bar')).toHaveLength(7)
    expect(screen.getAllByText('Loading alert details...').length).toBeGreaterThan(0)
  })

  it('renders hourly history bars without requiring decisions list data', async () => {
    mockApi.crowdsec.getDecisions.mockResolvedValue({
      data: { data: { decisions: [], count: 0 } },
    })

    renderDashboard()

    fireEvent.click(await screen.findByRole('button', { name: 'Hour' }))

    await waitFor(() => {
      expect(mockApi.crowdsec.getHistoryActivity).toHaveBeenCalledWith({ window: '24h', bucket: 'hour' })
    })
    await waitFor(() => {
      expect(screen.getAllByTestId('activity-bar')).toHaveLength(24)
    })
  })
})

function renderDashboard() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function makeHistoryActivity(window: '24h' | '7d', bucket: 'hour' | 'day'): HistoryActivityResponse {
  const count = bucket === 'hour' ? 24 : 7
  const stepMs = bucket === 'hour' ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000
  const start = bucket === 'hour'
    ? new Date('2026-04-23T00:00:00Z')
    : new Date('2026-04-18T00:00:00Z')
  return {
    window,
    bucket,
    generated_at: '2026-04-24T00:00:00Z',
    latest_snapshot_at: '2026-04-23T23:00:00Z',
    buckets: Array.from({ length: count }, (_, index) => ({
      ts: new Date(start.getTime() + index * stepMs).toISOString(),
      alerts: index === 0 ? 2 : 0,
      decisions: index === 1 ? 1 : 0,
    })),
  }
}
