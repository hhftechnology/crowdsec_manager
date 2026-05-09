import { Capacitor } from '@capacitor/core';
import { Preferences } from '@capacitor/preferences';

// Native (iOS / Android) → Capacitor Preferences (UserDefaults / SharedPreferences),
// which survives WebView storage eviction and app updates.
// Web / PWA → window.localStorage, preserving prior behaviour.
export const secureStorage = {
  async getItem(key: string): Promise<string | null> {
    if (Capacitor.isNativePlatform()) {
      const { value } = await Preferences.get({ key });
      return value ?? null;
    }
    return window.localStorage.getItem(key);
  },

  async setItem(key: string, value: string): Promise<void> {
    if (Capacitor.isNativePlatform()) {
      await Preferences.set({ key, value });
      return;
    }
    window.localStorage.setItem(key, value);
  },

  async removeItem(key: string): Promise<void> {
    if (Capacitor.isNativePlatform()) {
      await Preferences.remove({ key });
      return;
    }
    window.localStorage.removeItem(key);
  },
};
