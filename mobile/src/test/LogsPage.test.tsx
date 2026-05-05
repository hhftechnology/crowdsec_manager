import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import LogsPage from '@/pages/LogsPage';

const mockUseApi = vi.fn();

vi.mock('@/contexts/ApiContext', () => ({
  useApi: () => mockUseApi(),
}));

function createLogsApi() {
  return {
    logs: {
      crowdsec: vi.fn().mockResolvedValue({ logs: 'INFO crowdsec ready' }),
      traefik: vi.fn().mockResolvedValue({
        logs: 'INFO time="2026-05-04T15:06:24Z" level=info msg="a very long traefik access line that should stay inside the panel"',
      }),
      traefikAdvanced: vi.fn().mockResolvedValue({
        total_lines: 1,
        error_entries: [],
      }),
      structured: vi.fn().mockResolvedValue({ entries: [] }),
      streamUrl: vi.fn().mockReturnValue('ws://localhost/logs'),
    },
  };
}

describe('LogsPage module', () => {
  it('exports a function component', () => {
    expect(typeof LogsPage).toBe('function');
  });

  it('wraps Traefik controls and keeps the log viewer constrained', async () => {
    mockUseApi.mockReset();
    const api = createLogsApi();
    mockUseApi.mockReturnValue({ api });

    const { container } = render(<LogsPage />);

    fireEvent.click(screen.getByRole('button', { name: 'Traefik' }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Access' })).toBeInTheDocument();
    });

    const traefikButton = screen.getByRole('button', { name: 'Traefik' });
    const accessButton = screen.getByRole('button', { name: 'Access' });
    const errorButton = screen.getByRole('button', { name: 'Error' });
    expect(traefikButton.parentElement?.parentElement?.className).toContain('flex-wrap');
    expect(accessButton.parentElement?.className).toContain('flex-wrap');
    expect(errorButton).toBeInTheDocument();

    const logViewer = container.querySelector('.bg-surface-dark.font-mono');
    expect(logViewer?.className).toContain('max-w-full');
    expect(logViewer?.className).toContain('overflow-hidden');
    expect(logViewer?.querySelector('.overflow-x-hidden')).toBeTruthy();
  });
});
