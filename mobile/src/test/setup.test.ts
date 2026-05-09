import { describe, it, expect } from 'vitest';

// Smoke test — the real coverage of setup.ts is the entire test suite
// running successfully (the file is loaded as setupFiles in vitest.config.ts).
describe('test setup', () => {
  it('configures jsdom + jest-dom matchers', () => {
    expect(typeof window).toBe('object');
    expect(typeof window.localStorage.setItem).toBe('function');
  });

  it('mocks @capacitor/core globally with isNativePlatform=false on web', async () => {
    const { Capacitor } = await import('@capacitor/core');
    expect(Capacitor.isNativePlatform()).toBe(false);
    expect(Capacitor.getPlatform()).toBe('web');
  });
});
