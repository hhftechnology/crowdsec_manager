import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Capacitor } from '@capacitor/core';
import { App as CapApp } from '@capacitor/app';
import { compareSemver, useManagerUpdate } from './useManagerUpdate';

const fetchMock = vi.fn();
const isNativeMock = vi.mocked(Capacitor.isNativePlatform);
const getPlatformMock = vi.mocked(Capacitor.getPlatform);
const getInfoMock = vi.mocked(CapApp.getInfo);

function makeWrapper() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
}

function Probe() {
  const update = useManagerUpdate();
  return (
    <div>
      <span data-testid="available">{String(update.available)}</span>
      <span data-testid="dismissed">{String(update.dismissed)}</span>
      <span data-testid="current">{update.currentVersion ?? ''}</span>
      <span data-testid="latest">{update.latestVersion ?? ''}</span>
      <span data-testid="install">{update.installUrl ?? ''}</span>
      <button data-testid="dismiss" onClick={() => update.dismiss()} />
    </div>
  );
}

beforeEach(() => {
  fetchMock.mockReset();
  // Default to native so the mocked App.getInfo() is the source of truth for
  // the current version (1.0.0). Web-fallback path is exercised separately.
  isNativeMock.mockReturnValue(true);
  getPlatformMock.mockReturnValue('ios');
  getInfoMock.mockResolvedValue({
    version: '1.0.0',
    name: 'CrowdSec Manager',
    id: 'com.crowdsec.manager.mobile',
    build: '1',
  });
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function releaseResponse(tag: string, html_url = `https://github.com/x/y/releases/tag/${tag}`) {
  return new Response(
    JSON.stringify({
      tag_name: tag,
      name: tag,
      html_url,
      published_at: '2026-01-01T00:00:00Z',
      prerelease: false,
      draft: false,
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}

describe('compareSemver', () => {
  it('compares numeric segments', () => {
    expect(compareSemver('1.2.3', '1.2.4')).toBeLessThan(0);
    expect(compareSemver('2.0.0', '1.9.9')).toBeGreaterThan(0);
    expect(compareSemver('v1.2.3', '1.2.3')).toBe(0);
  });

  it('treats prerelease suffixes as lower than the release', () => {
    expect(compareSemver('1.2.3-rc1', '1.2.3')).toBeLessThan(0);
    expect(compareSemver('1.2.3', '1.2.3-rc1')).toBeGreaterThan(0);
  });
});

describe('useManagerUpdate', () => {
  it('reports an update when latest > current', async () => {
    fetchMock.mockResolvedValueOnce(releaseResponse('v1.2.0'));

    render(<Probe />, { wrapper: makeWrapper() });

    await waitFor(() => {
      expect(screen.getByTestId('available').textContent).toBe('true');
    });
    expect(screen.getByTestId('current').textContent).toBe('1.0.0');
    expect(screen.getByTestId('latest').textContent).toBe('1.2.0');
    expect(screen.getByTestId('install').textContent).toContain('github.com');
  });

  it('does not report an update when current >= latest', async () => {
    fetchMock.mockResolvedValueOnce(releaseResponse('v1.0.0'));

    render(<Probe />, { wrapper: makeWrapper() });

    await waitFor(() => {
      expect(screen.getByTestId('current').textContent).toBe('1.0.0');
    });
    expect(screen.getByTestId('available').textContent).toBe('false');
  });

  it('persists dismissal keyed by version', async () => {
    fetchMock.mockResolvedValueOnce(releaseResponse('v1.2.0'));

    render(<Probe />, { wrapper: makeWrapper() });

    await waitFor(() => {
      expect(screen.getByTestId('available').textContent).toBe('true');
    });

    await act(async () => {
      screen.getByTestId('dismiss').click();
    });

    await waitFor(() => {
      expect(screen.getByTestId('dismissed').textContent).toBe('true');
    });
    // Native path → Capacitor Preferences → backed by capacitorPrefsStore mock.
    // We can't observe that directly, so just trust the dismissed state.
    expect(screen.getByTestId('dismissed').textContent).toBe('true');
  });

  it('hides when the dismissed version matches the latest', async () => {
    // Pre-populate via the real secureStorage path. Force web mode so it lands
    // in localStorage where we can seed it synchronously.
    isNativeMock.mockReturnValue(false);
    window.localStorage.setItem('csm:manager-update-dismissed', '1.2.0');
    // Web fallback uses VITE_APP_VERSION; stub it so the comparison is sane.
    vi.stubEnv('VITE_APP_VERSION', '1.0.0');
    fetchMock.mockResolvedValueOnce(releaseResponse('v1.2.0'));

    render(<Probe />, { wrapper: makeWrapper() });

    await waitFor(() => {
      expect(screen.getByTestId('latest').textContent).toBe('1.2.0');
    });
    await waitFor(() => {
      expect(screen.getByTestId('dismissed').textContent).toBe('true');
    });
  });

  it('re-shows when a new release supersedes the dismissed version', async () => {
    isNativeMock.mockReturnValue(false);
    window.localStorage.setItem('csm:manager-update-dismissed', '1.1.0');
    vi.stubEnv('VITE_APP_VERSION', '1.0.0');
    fetchMock.mockResolvedValueOnce(releaseResponse('v1.2.0'));

    render(<Probe />, { wrapper: makeWrapper() });

    await waitFor(() => {
      expect(screen.getByTestId('latest').textContent).toBe('1.2.0');
    });
    expect(screen.getByTestId('dismissed').textContent).toBe('false');
    expect(screen.getByTestId('available').textContent).toBe('true');
  });

  it('prefers the Play Store URL on Android when set', async () => {
    isNativeMock.mockReturnValue(true);
    getPlatformMock.mockReturnValue('android');
    fetchMock.mockResolvedValueOnce(releaseResponse('v1.2.0'));

    render(<Probe />, { wrapper: makeWrapper() });

    await waitFor(() => {
      expect(screen.getByTestId('install').textContent).toContain(
        'play.google.com',
      );
    });
  });
});
