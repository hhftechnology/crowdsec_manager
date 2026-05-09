import { describe, expect, it, vi } from 'vitest';
import { Capacitor } from '@capacitor/core';
import { Preferences } from '@capacitor/preferences';
import { secureStorage } from './secureStorage';

// Re-resolve the spy on each call rather than caching at module scope —
// vitest with `isolate: false` can swap the spy reference between files and
// stale captures stop responding to mockReturnValue.
const setNative = (value: boolean) =>
  vi.mocked(Capacitor.isNativePlatform).mockReturnValue(value);

describe('secureStorage (web)', () => {
  it('reads, writes, and removes values via localStorage on web', async () => {
    setNative(false);

    expect(await secureStorage.getItem('k')).toBeNull();

    await secureStorage.setItem('k', 'v');
    expect(window.localStorage.getItem('k')).toBe('v');
    expect(await secureStorage.getItem('k')).toBe('v');

    await secureStorage.removeItem('k');
    expect(window.localStorage.getItem('k')).toBeNull();
    expect(await secureStorage.getItem('k')).toBeNull();
  });

  it('does not call Capacitor Preferences on web', async () => {
    setNative(false);
    vi.mocked(Preferences.set).mockClear();
    vi.mocked(Preferences.get).mockClear();
    vi.mocked(Preferences.remove).mockClear();

    await secureStorage.setItem('k', 'v');
    await secureStorage.getItem('k');
    await secureStorage.removeItem('k');
    expect(Preferences.set).not.toHaveBeenCalled();
    expect(Preferences.get).not.toHaveBeenCalled();
    expect(Preferences.remove).not.toHaveBeenCalled();
  });
});

describe('secureStorage (native)', () => {
  it('reads, writes, and removes values via Capacitor Preferences', async () => {
    setNative(true);

    expect(await secureStorage.getItem('k')).toBeNull();

    await secureStorage.setItem('k', 'v');
    expect(Preferences.set).toHaveBeenCalledWith({ key: 'k', value: 'v' });
    expect(await secureStorage.getItem('k')).toBe('v');

    await secureStorage.removeItem('k');
    expect(Preferences.remove).toHaveBeenCalledWith({ key: 'k' });
    expect(await secureStorage.getItem('k')).toBeNull();
  });

  it('does not touch localStorage on native', async () => {
    setNative(true);
    await secureStorage.setItem('k', 'v');
    expect(window.localStorage.getItem('k')).toBeNull();
  });
});
