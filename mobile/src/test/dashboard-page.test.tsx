import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import DashboardPage from '@/pages/DashboardPage';

const mockUseApi = vi.fn();

vi.mock('@/contexts/ApiContext', () => ({
  useApi: () => mockUseApi(),
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
    mockUseApi.mockReturnValue({ api });

    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText('Diagnostics Summary')).toBeInTheDocument();
    });

    expect(screen.getByText('Diagnostics Summary')).toBeInTheDocument();
    expect(screen.queryByText('API unreachable')).not.toBeInTheDocument();
  });

  it('shows retryable inline error when critical requests fail', async () => {
    mockUseApi.mockReset();
    const api = createBaseApi();
    api.health.getStack.mockRejectedValue(new TypeError('Failed to fetch'));
    api.health.getCrowdsec.mockRejectedValue(new TypeError('Failed to fetch'));
    api.health.getComplete.mockRejectedValue(new TypeError('Failed to fetch'));
    api.ip.getPublicIP.mockResolvedValue({ ip: '1.2.3.4' });
    api.crowdsec.alertsAnalysis.mockResolvedValue(null);
    mockUseApi.mockReturnValue({ api });

    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText('API unreachable')).toBeInTheDocument();
    });

    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });
});
