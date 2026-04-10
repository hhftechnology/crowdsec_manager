import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import SecurityPage from '@/pages/SecurityPage';

const mockUseApi = vi.fn();

vi.mock('@/contexts/ApiContext', () => ({
  useApi: () => mockUseApi(),
}));

vi.mock('@/lib/actionToast', () => ({
  showActionError: vi.fn(),
  showActionSuccess: vi.fn(),
}));

function createApi() {
  return {
    ip: {
      checkBlocked: vi.fn(),
      checkSecurity: vi.fn(),
      unban: vi.fn(),
    },
    crowdsec: {
      decisionsAnalysis: vi.fn(),
      alertsAnalysis: vi.fn(),
      metrics: vi.fn(),
      decisionHistory: vi.fn(),
      reapplyDecision: vi.fn(),
      addDecision: vi.fn(),
      deleteDecision: vi.fn(),
      importDecisions: vi.fn(),
      inspectAlert: vi.fn(),
      deleteAlert: vi.fn(),
    },
  };
}

describe('SecurityPage', () => {
  it('requests paged decisions and advances with next navigation', async () => {
    mockUseApi.mockReset();
    const api = createApi();
    api.crowdsec.decisionsAnalysis
      .mockResolvedValueOnce({
        decisions: [{ id: 1, type: 'ban', value: '1.1.1.1', scope: 'Ip', duration: '4h' }],
        count: 1,
        total: 21,
        limit: 20,
        offset: 0,
      })
      .mockResolvedValueOnce({
        decisions: [{ id: 2, type: 'ban', value: '2.2.2.2', scope: 'Ip', duration: '4h' }],
        count: 1,
        total: 21,
        limit: 20,
        offset: 20,
      });
    api.crowdsec.alertsAnalysis.mockResolvedValue({ alerts: [], count: 0 });
    api.crowdsec.metrics.mockResolvedValue(null);
    api.crowdsec.decisionHistory.mockResolvedValue({ decisions: [], count: 0, total: 0 });
    mockUseApi.mockReturnValue({ api });

    render(<SecurityPage />);

    await waitFor(() => {
      expect(api.crowdsec.decisionsAnalysis).toHaveBeenCalledWith({ limit: 20, offset: 0 });
    });

    const decisionsTab = screen.getByRole('tab', { name: 'Decisions' });
    fireEvent.mouseDown(decisionsTab);
    fireEvent.click(decisionsTab);
    await waitFor(() => {
      expect(decisionsTab).toHaveAttribute('data-state', 'active');
      expect(screen.getByText('1.1.1.1')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Next' }));

    await waitFor(() => {
      expect(api.crowdsec.decisionsAnalysis).toHaveBeenLastCalledWith({ limit: 20, offset: 20 });
    });
  });

  it('reapplies a historical decision from the history tab', async () => {
    mockUseApi.mockReset();
    const api = createApi();
    api.crowdsec.decisionsAnalysis.mockResolvedValue({ decisions: [], count: 0, total: 0, limit: 20, offset: 0 });
    api.crowdsec.alertsAnalysis.mockResolvedValue({ alerts: [], count: 0 });
    api.crowdsec.metrics.mockResolvedValue(null);
    api.crowdsec.decisionHistory.mockResolvedValue({
      decisions: [
        {
          id: 11,
          dedupe_key: 'dk',
          decision_id: 8,
          alert_id: 3,
          origin: 'crowdsec',
          type: 'ban',
          scope: 'Ip',
          value: '5.5.5.5',
          duration: '24h',
          scenario: 'ssh-bf',
          created_at: '2026-03-20T12:00:00Z',
          is_stale: true,
          first_seen_at: '2026-03-20T12:00:00Z',
          last_seen_at: '2026-03-20T13:00:00Z',
          last_snapshot_at: '2026-03-20T13:00:00Z',
        },
      ],
      count: 1,
      total: 1,
    });
    api.crowdsec.reapplyDecision.mockResolvedValue({ message: 'ok', data: { message: 'ok' } });
    mockUseApi.mockReturnValue({ api });

    render(<SecurityPage />);

    await waitFor(() => {
      expect(screen.getByRole('tab', { name: 'History' })).toBeInTheDocument();
    });

    const historyTab = screen.getByRole('tab', { name: 'History' });
    fireEvent.mouseDown(historyTab);
    fireEvent.click(historyTab);
    await waitFor(() => {
      expect(historyTab).toHaveAttribute('data-state', 'active');
      expect(screen.getByText('5.5.5.5')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Reapply' }));
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Reapply' })).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole('button', { name: 'Reapply' }));

    await waitFor(() => {
      expect(api.crowdsec.reapplyDecision).toHaveBeenCalledWith({
        id: 11,
        type: 'ban',
        duration: '24h',
      });
    });
  });
});
