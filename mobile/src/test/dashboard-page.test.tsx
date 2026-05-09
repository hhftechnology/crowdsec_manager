import { render, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import DashboardPage from '@/pages/DashboardPage';
import type { DiagnosticResult } from '@/lib/api';

const mockUseApi = vi.fn();

vi.mock('@/contexts/ApiContext', () => ({
  useApi: () => mockUseApi(),
}));

vi.mock('@/components/dashboard/ManagerUpdateCard', () => ({
  ManagerUpdateCard: () => null,
}));

function createBaseApi() {
  return {
    health: {
      getStack: vi.fn(),
      getCrowdsec: vi.fn(),
      getComplete: vi.fn(),
    },
    ip: {
      getPublicIP: vi.fn(),
    },
    crowdsec: {
      alertsAnalysis: vi.fn(),
      decisionsSummary: vi.fn(),
      historyActivity: vi.fn(),
    },
  };
}

describe('DashboardPage', () => {
  it('renders dashboard skeleton during initial load', () => {
    mockUseApi.mockReset();
    const api = createBaseApi();
    api.health.getStack.mockReturnValue(new Promise(() => {}));
    api.health.getCrowdsec.mockReturnValue(new Promise(() => {}));
    api.health.getComplete.mockReturnValue(new Promise(() => {}));
    api.ip.getPublicIP.mockReturnValue(new Promise(() => {}));
    api.crowdsec.alertsAnalysis.mockReturnValue(new Promise(() => {}));
    api.crowdsec.decisionsSummary.mockReturnValue(new Promise(() => {}));
    api.crowdsec.historyActivity.mockReturnValue(new Promise(() => {}));
    mockUseApi.mockReturnValue({ api });

    render(<DashboardPage />);

    expect(screen.getByLabelText('Loading dashboard')).toBeInTheDocument();
  });

  it('renders partial dashboard content when optional requests fail', async () => {
    mockUseApi.mockReset();
    const api = createBaseApi();
    api.health.getStack.mockResolvedValue({
      containers: [{ id: 'abc', name: 'crowdsec', running: true, status: 'running' }],
      allRunning: true,
      timestamp: '2026-03-20T12:00:00Z',
    });
    api.health.getCrowdsec.mockResolvedValue({
      status: 'healthy',
      checks: {},
      timestamp: '2026-03-20T12:00:00Z',
    });
    api.health.getComplete.mockResolvedValue({
      bouncers: [{ name: 'traefik', valid: true, ip_address: '10.0.0.1' }],
      decisions: [{ id: '1' }],
      traefik_integration: true,
      timestamp: '2026-03-20T12:00:00Z',
    });
    api.ip.getPublicIP.mockRejectedValue(new TypeError('Failed to fetch'));
    api.crowdsec.alertsAnalysis.mockResolvedValue(null);
    api.crowdsec.decisionsSummary.mockRejectedValue(new Error('summary unavailable'));
    api.crowdsec.historyActivity.mockRejectedValue(new Error('activity unavailable'));
    mockUseApi.mockReturnValue({ api });

    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText('Today, calm.')).toBeInTheDocument();
    });

    // Decisions stat block reflects diagnostic decisions count
    const decisionsLabel = screen.getByText('Decisions');
    const decisionsCard = decisionsLabel.parentElement;
    expect(decisionsCard).toBeTruthy();
    expect(within(decisionsCard as HTMLElement).getByText('1')).toBeInTheDocument();
    expect(screen.queryByText('API unreachable')).not.toBeInTheDocument();
  });

  it('renders dashboard content when diagnostics omit bouncers', async () => {
    mockUseApi.mockReset();
    const api = createBaseApi();
    api.health.getStack.mockResolvedValue({
      containers: [{ id: 'abc', name: 'crowdsec', running: true, status: 'running' }],
      allRunning: true,
      timestamp: '2026-03-20T12:00:00Z',
    });
    api.health.getCrowdsec.mockResolvedValue({
      status: 'healthy',
      checks: {},
      timestamp: '2026-03-20T12:00:00Z',
    });
    api.health.getComplete.mockResolvedValue({
      decisions: [{ id: '1' }],
      timestamp: '2026-03-20T12:00:00Z',
    } as unknown as DiagnosticResult);
    api.ip.getPublicIP.mockResolvedValue({ ip: '1.2.3.4' });
    api.crowdsec.alertsAnalysis.mockResolvedValue(null);
    api.crowdsec.decisionsSummary.mockResolvedValue({ count: 1 });
    api.crowdsec.historyActivity.mockResolvedValue({ buckets: [] });
    mockUseApi.mockReturnValue({ api });

    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText('Today, calm.')).toBeInTheDocument();
    });

    expect(screen.getAllByText('Containers').length).toBeGreaterThan(0);
    expect(screen.queryByText('API unreachable')).not.toBeInTheDocument();
  });

  it('renders theme-aware security overview counts and top scenarios', async () => {
    mockUseApi.mockReset();
    const api = createBaseApi();
    api.health.getStack.mockResolvedValue({
      containers: [{ id: 'abc', name: 'crowdsec', running: true, status: 'running' }],
      allRunning: true,
      timestamp: '2026-03-20T12:00:00Z',
    });
    api.health.getCrowdsec.mockResolvedValue({
      status: 'healthy',
      checks: {},
      timestamp: '2026-03-20T12:00:00Z',
    });
    api.health.getComplete.mockResolvedValue({
      bouncers: [],
      decisions: [],
      timestamp: '2026-03-20T12:00:00Z',
    } as unknown as DiagnosticResult);
    api.ip.getPublicIP.mockResolvedValue({ ip: '1.2.3.4' });
    api.crowdsec.alertsAnalysis.mockResolvedValue({
      count: 3,
      alerts: [
        { id: '1', scenario: 'crowdsecurity/http-probing' },
        { id: '2', scenario: 'crowdsecurity/http-probing' },
        { id: '3', scenario: 'crowdsecurity/http-bad-user-agent' },
      ],
    });
    api.crowdsec.decisionsSummary.mockResolvedValue({
      count: 5,
      types: {
        captcha: 4,
        ban: 1,
      },
    });
    api.crowdsec.historyActivity.mockResolvedValue({ buckets: [] });
    mockUseApi.mockReturnValue({ api });

    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText('security overview')).toBeInTheDocument();
    });

    const overviewCard = screen.getByText('security overview').closest('.rounded-lg');
    expect(overviewCard?.className).toContain('bg-surface-card');
    expect(overviewCard?.className).toContain('dark:bg-surface-dark');
    expect(within(overviewCard as HTMLElement).getByText('Bans')).toBeInTheDocument();
    expect(within(overviewCard as HTMLElement).getByText('Captchas')).toBeInTheDocument();
    expect(within(overviewCard as HTMLElement).getByText('Whitelisted')).toBeInTheDocument();
    const bansRow = within(overviewCard as HTMLElement).getByText('Bans').closest('div');
    const captchasRow = within(overviewCard as HTMLElement).getByText('Captchas').closest('div');
    expect(within(bansRow as HTMLElement).getByText('1')).toBeInTheDocument();
    expect(within(captchasRow as HTMLElement).getByText('4')).toBeInTheDocument();
    expect(within(overviewCard as HTMLElement).getByText('crowdsecurity/http-probing')).toBeInTheDocument();
    expect(within(overviewCard as HTMLElement).getByText('crowdsecurity/http-bad-user-agent')).toBeInTheDocument();
  });

  it('shows count-only decision summaries as other decisions instead of bans', async () => {
    mockUseApi.mockReset();
    const api = createBaseApi();
    api.health.getStack.mockResolvedValue({
      containers: [{ id: 'abc', name: 'crowdsec', running: true, status: 'running' }],
      allRunning: true,
      timestamp: '2026-03-20T12:00:00Z',
    });
    api.health.getCrowdsec.mockResolvedValue({
      status: 'healthy',
      checks: {},
      timestamp: '2026-03-20T12:00:00Z',
    });
    api.health.getComplete.mockResolvedValue({
      bouncers: [],
      decisions: [],
      timestamp: '2026-03-20T12:00:00Z',
    } as unknown as DiagnosticResult);
    api.ip.getPublicIP.mockResolvedValue({ ip: '1.2.3.4' });
    api.crowdsec.alertsAnalysis.mockResolvedValue({ count: 0, alerts: [] });
    api.crowdsec.decisionsSummary.mockResolvedValue({ count: 3 });
    api.crowdsec.historyActivity.mockResolvedValue({ buckets: [] });
    mockUseApi.mockReturnValue({ api });

    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText('security overview')).toBeInTheDocument();
    });

    const overviewCard = screen.getByText('security overview').closest('.rounded-lg');
    const bansRow = within(overviewCard as HTMLElement).getByText('Bans').closest('div');
    const captchasRow = within(overviewCard as HTMLElement).getByText('Captchas').closest('div');
    const otherRow = within(overviewCard as HTMLElement).getByText('Other').closest('div');
    expect(within(bansRow as HTMLElement).getByText('0')).toBeInTheDocument();
    expect(within(captchasRow as HTMLElement).getByText('0')).toBeInTheDocument();
    expect(within(otherRow as HTMLElement).getByText('3')).toBeInTheDocument();
  });

  it('shows retryable inline error when critical requests fail', async () => {
    mockUseApi.mockReset();
    const api = createBaseApi();
    api.health.getStack.mockRejectedValue(new TypeError('Failed to fetch'));
    api.health.getCrowdsec.mockRejectedValue(new TypeError('Failed to fetch'));
    api.health.getComplete.mockRejectedValue(new TypeError('Failed to fetch'));
    api.ip.getPublicIP.mockResolvedValue({ ip: '1.2.3.4' });
    api.crowdsec.alertsAnalysis.mockResolvedValue(null);
    api.crowdsec.decisionsSummary.mockResolvedValue({ count: 0 });
    api.crowdsec.historyActivity.mockResolvedValue({ buckets: [] });
    mockUseApi.mockReturnValue({ api });

    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText('API unreachable')).toBeInTheDocument();
    });

    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });
});
