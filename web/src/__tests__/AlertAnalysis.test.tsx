import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import AlertAnalysis from '@/pages/AlertAnalysis'
import { SearchProvider } from '@/contexts/SearchContext'

const mockApi = vi.hoisted(() => ({
  crowdsec: {
    getAlertsAnalysis: vi.fn(),
  },
}))

const mockCrowdsecAPI = vi.hoisted(() => ({
  inspectAlert: vi.fn(),
  deleteAlert: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  default: mockApi,
}))

vi.mock('@/lib/api/crowdsec', () => ({
  crowdsecAPI: mockCrowdsecAPI,
}))

vi.mock('sonner', () => ({
  toast: {
    error: vi.fn(),
    info: vi.fn(),
    success: vi.fn(),
  },
}))

vi.mock('@/components/alerts/AlertCard', () => ({
  AlertCard: ({ alert }: { alert: { value: string; scenario: string } }) => (
    <article>
      <span>{alert.value}</span>
      <span>{alert.scenario}</span>
    </article>
  ),
}))

vi.mock('@/components/charts', () => ({
  ChartCard: ({ title, children }: { title: string; children: ReactNode }) => (
    <section aria-label={title}>{children}</section>
  ),
  AreaTimeline: () => <div />,
  BarDistribution: () => <div />,
  ThreatMap: () => <div />,
}))

describe('AlertAnalysis', () => {
  afterEach(() => {
    cleanup()
  })

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('does not show the empty state while an empty alerts result is refreshing', async () => {
    let resolveRefresh: (value: unknown) => void = () => {}
    mockApi.crowdsec.getAlertsAnalysis
      .mockResolvedValueOnce(emptyAlertsResponse())
      .mockReturnValueOnce(new Promise((resolve) => {
        resolveRefresh = resolve
      }))

    renderAlertAnalysis()

    expect(await screen.findByText('No alerts found')).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: /refresh/i })[0])

    await waitFor(() => {
      expect(screen.queryByText('No alerts found')).not.toBeInTheDocument()
    })
    expect(screen.getByText('Refreshing alerts...')).toBeInTheDocument()

    resolveRefresh(emptyAlertsResponse())
    await waitFor(() => {
      expect(mockApi.crowdsec.getAlertsAnalysis).toHaveBeenCalledTimes(2)
    })
  })

  it('keeps same-filter last non-empty alert data after a transient zero response', async () => {
    mockApi.crowdsec.getAlertsAnalysis
      .mockResolvedValueOnce(nonEmptyAlertsResponse())
      .mockResolvedValueOnce(emptyAlertsResponse())

    renderAlertAnalysis()

    expect(await screen.findByText('198.51.100.10')).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: /refresh/i })[0])

    await waitFor(() => {
      expect(mockApi.crowdsec.getAlertsAnalysis).toHaveBeenCalledTimes(2)
    })
    expect(screen.getByText('198.51.100.10')).toBeInTheDocument()
    expect(screen.queryByText('No alerts found')).not.toBeInTheDocument()
  })

  it('shows a real empty state after changing filters', async () => {
    mockApi.crowdsec.getAlertsAnalysis
      .mockResolvedValueOnce(nonEmptyAlertsResponse())
      .mockResolvedValueOnce(emptyAlertsResponse())

    renderAlertAnalysis()

    expect(await screen.findByText('198.51.100.10')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText(/^Scenario$/), { target: { value: 'missing-scenario' } })
    fireEvent.click(screen.getByRole('button', { name: /apply filters/i }))

    await waitFor(() => {
      expect(mockApi.crowdsec.getAlertsAnalysis).toHaveBeenLastCalledWith({ scenario: 'missing-scenario' })
    })
    expect(await screen.findByText('No alerts found')).toBeInTheDocument()
    expect(screen.queryByText('198.51.100.10')).not.toBeInTheDocument()
  })
})

function renderAlertAnalysis() {
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
        <SearchProvider>
          <AlertAnalysis />
        </SearchProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function emptyAlertsResponse() {
  return {
    data: {
      data: {
        alerts: [],
        count: 0,
      },
    },
  }
}

function nonEmptyAlertsResponse() {
  return {
    data: {
      data: {
        alerts: [
          {
            id: 123,
            scenario: 'crowdsecurity/http-probing',
            scope: 'Ip',
            value: '198.51.100.10',
            origin: 'crowdsec',
            type: 'ban',
            start_at: '2026-05-06T14:51:43Z',
            events_count: 1,
          },
        ],
        count: 1,
      },
    },
  }
}
