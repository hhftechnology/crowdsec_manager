import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Capacitor } from '@capacitor/core';
import { SecureStoragePlugin } from 'capacitor-secure-storage-plugin';
import { secureStorage } from './secureStorage';

// Stash the original isNativePlatform reference once. Vitest's
// `restoreAllMocks` in the global afterEach can leave the spy in a degraded
// state across many test files, so we re-bind the original function here
// before each test and rely on direct assignment for native-mode tests.
const originalIsNative = Capacitor.isNativePlatform;

beforeEach(() => {
  (Capacitor as { isNativePlatform: () => boolean }).isNativePlatform =
    originalIsNative;
});

afterEach(() => {
  (Capacitor as { isNativePlatform: () => boolean }).isNativePlatform =
    originalIsNative;
});

const setNative = (value: boolean) => {
  (Capacitor as { isNativePlatform: () => boolean }).isNativePlatform =
    () => value;
};

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

  it('does not call the secure storage plugin on web', async () => {
    setNative(false);
    vi.mocked(SecureStoragePlugin.set).mockClear();
    vi.mocked(SecureStoragePlugin.get).mockClear();
    vi.mocked(SecureStoragePlugin.remove).mockClear();

    await secureStorage.setItem('k', 'v');
    await secureStorage.getItem('k');
    await secureStorage.removeItem('k');
    expect(SecureStoragePlugin.set).not.toHaveBeenCalled();
    expect(SecureStoragePlugin.get).not.toHaveBeenCalled();
    expect(SecureStoragePlugin.remove).not.toHaveBeenCalled();
  });
});

describe('secureStorage (native)', () => {
  it('reads, writes, and removes values via the secure storage plugin', async () => {
    setNative(true);

    expect(await secureStorage.getItem('k')).toBeNull();

    await secureStorage.setItem('k', 'v');
    expect(SecureStoragePlugin.set).toHaveBeenCalledWith({ key: 'k', value: 'v' });
    expect(await secureStorage.getItem('k')).toBe('v');

    await secureStorage.removeItem('k');
    expect(SecureStoragePlugin.remove).toHaveBeenCalledWith({ key: 'k' });
    expect(await secureStorage.getItem('k')).toBeNull();
  });

  it('does not touch localStorage on native', async () => {
    setNative(true);
    await secureStorage.setItem('k', 'v');
    expect(window.localStorage.getItem('k')).toBeNull();
  });

  it('translates a missing-key plugin reject into null', async () => {
    setNative(true);
    expect(await secureStorage.getItem('does-not-exist')).toBeNull();
  });

  it('swallows plugin errors when removing a missing key', async () => {
    setNative(true);
    await expect(
      secureStorage.removeItem('does-not-exist'),
    ).resolves.toBeUndefined();
  });
});
