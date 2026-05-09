import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import AllowlistsPage from '@/pages/AllowlistsPage';

const mockApi = vi.hoisted(() => ({
  allowlist: {
    list: vi.fn(),
    inspect: vi.fn(),
    create: vi.fn(),
    addEntries: vi.fn(),
    removeEntries: vi.fn(),
    delete: vi.fn(),
  },
}));

vi.mock('@/contexts/ApiContext', () => ({
  useApi: () => ({ api: mockApi }),
}));

vi.mock('@/lib/actionToast', () => ({
  showActionError: vi.fn(),
  showActionSuccess: vi.fn(),
}));

describe('AllowlistsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockApi.allowlist.list.mockResolvedValue({
      allowlists: [{ name: 'my_allowlist', description: 'Trusted IPs', size: 0 }],
      count: 1,
    });
  });

  it('exports a function component', () => {
    expect(typeof AllowlistsPage).toBe('function');
  });

  it('renders empty inspected allowlist items without crashing', async () => {
    mockApi.allowlist.inspect.mockResolvedValue({
      name: 'my_allowlist',
      description: 'Trusted IPs',
      items: null,
      count: 0,
    });

    render(
      <MemoryRouter>
        <AllowlistsPage />
      </MemoryRouter>,
    );

    await screen.findByText('my_allowlist');
    fireEvent.click(screen.getByRole('button', { name: /inspect/i }));

    await waitFor(() => {
      expect(mockApi.allowlist.inspect).toHaveBeenCalledWith('my_allowlist');
    });
    expect(await screen.findByText('No entries in this allowlist.')).toBeInTheDocument();
  });
});
