import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import HubPage from '@/pages/HubPage';

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
    hub: {
      list: vi.fn(),
      categories: vi.fn(),
      preferences: vi.fn(),
      history: vi.fn(),
      items: vi.fn(),
      preference: vi.fn(),
      install: vi.fn(),
      remove: vi.fn(),
      manualApply: vi.fn(),
      updatePreference: vi.fn(),
      historyById: vi.fn(),
      upgradeAll: vi.fn(),
    },
  };
}

describe('HubPage', () => {
  it('shows grouped all-category hub overview on first load', async () => {
    mockUseApi.mockReset();
    const api = createApi();
    api.hub.list.mockResolvedValue({
      collections: [{ name: 'base/http-cve', status: 'enabled' }],
      scenarios: [{ name: 'crowdsecurity/ssh-bf', status: 'enabled' }],
    });
    api.hub.categories.mockResolvedValue([
      { key: 'collections', label: 'Collections', cli_type: 'collections', container_dir: '/etc/crowdsec/collections', supports_direct: true },
      { key: 'scenarios', label: 'Scenarios', cli_type: 'scenarios', container_dir: '/etc/crowdsec/scenarios', supports_direct: true },
    ]);
    api.hub.preferences.mockResolvedValue([]);
    api.hub.history.mockResolvedValue([]);
    mockUseApi.mockReturnValue({ api });

    render(<HubPage />);

    await waitFor(() => {
      expect(screen.getByText('All category overview')).toBeInTheDocument();
    });

    expect(screen.getByText('base/http-cve')).toBeInTheDocument();
    expect(screen.getByText('crowdsecurity/ssh-bf')).toBeInTheDocument();
    expect(api.hub.items).not.toHaveBeenCalled();
  });
});
