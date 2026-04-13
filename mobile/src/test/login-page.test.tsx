import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import LoginPage from '@/pages/LoginPage';

const mockUseApi = vi.fn();
const mockNavigate = vi.fn();

vi.mock('@/contexts/ApiContext', () => ({
  useApi: () => mockUseApi(),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>(
    'react-router-dom',
  );
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

describe('LoginPage', () => {
  beforeEach(() => {
    mockUseApi.mockReset();
    mockNavigate.mockReset();
    mockUseApi.mockReturnValue({
      login: vi.fn().mockResolvedValue(false),
      isLoading: false,
      error: null,
    });
  });

  it('shows proxy fields only in proxy mode and blocks incomplete proxy submissions', async () => {
    render(<LoginPage />);

    expect(screen.queryByLabelText('Proxy username')).not.toBeInTheDocument();

    const proxyTab = screen.getByRole('tab', { name: 'Proxy' });
    fireEvent.mouseDown(proxyTab);
    fireEvent.click(proxyTab);

    await waitFor(() => {
      expect(screen.getByLabelText('Proxy username')).toBeInTheDocument();
    });
    expect(screen.getByLabelText('Proxy password')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Connect' })).toBeDisabled();

    fireEvent.change(screen.getByLabelText('Server URL'), {
      target: { value: 'proxy.example.com' },
    });
    fireEvent.change(screen.getByLabelText('Proxy username'), {
      target: { value: 'alice' },
    });
    fireEvent.change(screen.getByLabelText('Proxy password'), {
      target: { value: 'secret' },
    });

    expect(screen.getByRole('button', { name: 'Connect' })).toBeEnabled();
  });

  it('shows pangolin fields and keeps connect disabled until token is provided', async () => {
    render(<LoginPage />);

    const pangolinTab = screen.getByRole('tab', { name: 'Pangolin' });
    fireEvent.mouseDown(pangolinTab);
    fireEvent.click(pangolinTab);

    await waitFor(() => {
      expect(
        screen.getByLabelText('Pangolin access token'),
      ).toBeInTheDocument();
    });
    expect(
      screen.queryByLabelText('Token query parameter'),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Connect' })).toBeDisabled();

    fireEvent.click(screen.getByRole('button', { name: 'Show' }));
    expect(screen.getByLabelText('Token query parameter')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Pangolin URL'), {
      target: { value: 'pangolin.example.com' },
    });
    expect(screen.getByRole('button', { name: 'Connect' })).toBeDisabled();

    fireEvent.change(screen.getByLabelText('Pangolin access token'), {
      target: { value: 'pp6evkhe.3kyqq4a7eay6rp6ow6dacallhm' },
    });
    expect(screen.getByRole('button', { name: 'Connect' })).toBeEnabled();
  });
});
