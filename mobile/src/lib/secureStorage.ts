import { Capacitor } from '@capacitor/core';
import { SecureStoragePlugin } from 'capacitor-secure-storage-plugin';

// Native (iOS / Android) → SecureStoragePlugin, which writes to the iOS
// Keychain and Android EncryptedSharedPreferences (Keystore-backed). This
// keeps the connection profile's `proxyPassword` / `pangolinToken` encrypted
// at rest, satisfying the CodeQL "clear-text storage of sensitive
// information" rule and surviving WebView storage eviction.
//
// Web / PWA → window.localStorage. There is no equivalent OS-level keychain
// in the browser; users on the PWA build accept the same risk profile that
// localStorage already had pre-this change.
//
// `SecureStoragePlugin.get` rejects when the key is missing — translate that
// into `null` so callers can use a uniform "absent" return value.
export const secureStorage = {
  async getItem(key: string): Promise<string | null> {
    if (Capacitor.isNativePlatform()) {
      try {
        const { value } = await SecureStoragePlugin.get({ key });
        return value ?? null;
      } catch {
        return null;
      }
    }
    return window.localStorage.getItem(key);
  },

  async setItem(key: string, value: string): Promise<void> {
    if (Capacitor.isNativePlatform()) {
      await SecureStoragePlugin.set({ key, value });
      return;
    }
    window.localStorage.setItem(key, value);
  },

  async removeItem(key: string): Promise<void> {
    if (Capacitor.isNativePlatform()) {
      try {
        await SecureStoragePlugin.remove({ key });
      } catch {
        // Plugin throws if the key doesn't exist — same effect as removal.
      }
      return;
    }
    window.localStorage.removeItem(key);
  },
};
