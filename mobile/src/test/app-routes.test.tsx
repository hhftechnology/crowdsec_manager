import type { ReactNode } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockUseApi = vi.hoisted(() => vi.fn());
const dashboardDeferred = vi.hoisted(() => {
  let resolve!: () => void;
  const promise = new Promise<void>((res) => {
    resolve = res;
  });

  return {
    promise,
    resolve,
  };
});

vi.mock('@/contexts/ApiContext', () => ({
  useApi: () => mockUseApi(),
  ApiProvider: ({ children }: { children: ReactNode }) => children,
}));

vi.mock('@/pages/LoginPage', () => ({
  default: () => <div>Login screen</div>,
}));

vi.mock('@/pages/DashboardPage', async () => {
  await dashboardDeferred.promise;
  return {
    default: () => <div>Dashboard route ready</div>,
  };
});

vi.mock('@/pages/SecurityPage', () => ({
  default: () => <div>Security page</div>,
}));

vi.mock('@/pages/LogsPage', () => ({
  default: () => <div>Logs page</div>,
}));

vi.mock('@/pages/ManagementPage', () => ({
  default: () => <div>Management page</div>,
}));

vi.mock('@/pages/AllowlistsPage', () => ({
  default: () => <div>Allowlists page</div>,
}));

vi.mock('@/pages/ScenariosPage', () => ({
  default: () => <div>Scenarios page</div>,
}));

vi.mock('@/pages/HubPage', () => ({
  default: () => <div>Hub page</div>,
}));

vi.mock('@/pages/ContainersPage', () => ({
  default: () => <div>Containers page</div>,
}));

vi.mock('@/pages/TerminalPage', () => ({
  default: () => <div>Terminal page</div>,
}));

vi.mock('@/pages/MorePage', () => ({
  default: () => <div>More page</div>,
}));

vi.mock('@/pages/AboutPage', () => ({
  default: () => <div>About page</div>,
}));

vi.mock('@/pages/NotFound', () => ({
  default: () => <div>Not found</div>,
}));

vi.mock('@/components/BottomNav', () => ({
  BottomNav: () => <div>Bottom nav</div>,
}));

vi.mock('@/components/OfflineConnectionBanner', () => ({
  OfflineConnectionBanner: () => null,
}));

vi.mock('@/components/Onboarding', () => ({
  Onboarding: () => <div>Onboarding</div>,
}));

describe('AppRoutes', () => {
  beforeEach(() => {
    mockUseApi.mockReset();
    localStorage.setItem('csm_onboarding_complete', 'true');
  });

  it('renders login immediately for unauthenticated users', async () => {
    mockUseApi.mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
    });

    const { AppRoutes } = await import('@/App');

    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <AppRoutes />
      </MemoryRouter>,
    );

    expect(screen.getByText('Login screen')).toBeInTheDocument();
  });

  it('shows lazy route fallback before the dashboard route resolves', async () => {
    mockUseApi.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
    });

    const { AppRoutes } = await import('@/App');

    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <AppRoutes />
      </MemoryRouter>,
    );

    expect(screen.getByLabelText('Loading dashboard')).toBeInTheDocument();

    dashboardDeferred.resolve();

    await waitFor(() => {
      expect(screen.getByText('Dashboard route ready')).toBeInTheDocument();
    });
  });
});
