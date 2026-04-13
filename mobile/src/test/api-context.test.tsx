import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiProvider, useApi } from '@/contexts/ApiContext';
import type { ConnectionProfileDraft } from '@/lib/connection';

function createDraft(overrides: Partial<ConnectionProfileDraft> = {}): ConnectionProfileDraft {
  return {
    mode: 'direct',
    baseUrl: '',
    allowInsecure: false,
    proxyUsername: '',
    proxyPassword: '',
    pangolinToken: '',
    pangolinTokenParam: 'p_token',
    ...overrides,
  };
}

function Harness({ draft }: { draft: ConnectionProfileDraft }) {
  const { connectionProfile, error, login, logout } = useApi();

  return (
    <div>
      <button type="button" onClick={() => void login(draft)}>Login</button>
      <button type="button" onClick={logout}>Logout</button>
      <div data-testid="base-url">{connectionProfile?.baseUrl ?? ''}</div>
      <div data-testid="mode">{connectionProfile?.mode ?? ''}</div>
      <div data-testid="error">{error ?? ''}</div>
    </div>
  );
}

describe('ApiContext', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('rejects explicit http urls when insecure mode is off', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    render(
      <ApiProvider>
        <Harness draft={createDraft({ baseUrl: 'http://10.0.0.1:8080' })} />
      </ApiProvider>,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Login' }));

    await waitFor(() => {
      expect(screen.getByTestId('error')).toHaveTextContent('HTTPS is required in secure mode');
    });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('falls back from https to http when insecure mode is enabled', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new Error('Failed to fetch'))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ success: true, data: { containers: [], allRunning: true } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );

    render(
      <ApiProvider>
        <Harness draft={createDraft({ baseUrl: '10.0.0.1:8080', allowInsecure: true })} />
      </ApiProvider>,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Login' }));

    await waitFor(() => {
      expect(screen.getByTestId('base-url')).toHaveTextContent('http://10.0.0.1:8080');
    });

    expect(fetchSpy).toHaveBeenNthCalledWith(
      1,
      'https://10.0.0.1:8080/api/health/stack',
      expect.objectContaining({ method: 'GET' }),
    );
    expect(fetchSpy).toHaveBeenNthCalledWith(
      2,
      'http://10.0.0.1:8080/api/health/stack',
      expect.objectContaining({ method: 'GET' }),
    );
    expect(JSON.parse(localStorage.getItem('csm_connection_profile') || '{}')).toMatchObject({
      baseUrl: 'http://10.0.0.1:8080',
      allowInsecure: true,
    });
  });

  it('persists the full profile and clears it on logout', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ success: true, data: { containers: [], allRunning: true } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    render(
      <ApiProvider>
        <Harness draft={createDraft({
          mode: 'proxy-basic',
          baseUrl: 'proxy.example.com',
          proxyUsername: 'alice',
          proxyPassword: 'secret',
        })} />
      </ApiProvider>,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Login' }));

    await waitFor(() => {
      expect(screen.getByTestId('mode')).toHaveTextContent('proxy-basic');
    });

    expect(JSON.parse(localStorage.getItem('csm_connection_profile') || '{}')).toMatchObject({
      mode: 'proxy-basic',
      baseUrl: 'https://proxy.example.com',
      proxyUsername: 'alice',
      proxyPassword: 'secret',
    });

    fireEvent.click(screen.getByRole('button', { name: 'Logout' }));

    await waitFor(() => {
      expect(screen.getByTestId('base-url')).toHaveTextContent('');
    });
    expect(localStorage.getItem('csm_connection_profile')).toBeNull();
  });
});
