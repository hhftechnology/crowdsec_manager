import '@testing-library/jest-dom';
import { cleanup } from '@testing-library/react';
import { afterEach, vi } from 'vitest';

// Mock Capacitor plugins globally so module-level `vi.mock` in individual test
// files doesn't leak under `isolate: false`. Tests can override behaviour with
// `vi.mocked(...).mockReturnValue(...)` / `mockResolvedValue(...)`.
vi.mock('@capacitor/core', () => ({
  Capacitor: {
    isNativePlatform: vi.fn(() => false),
    getPlatform: vi.fn(() => 'web'),
  },
}));

vi.mock('@capacitor/app', () => ({
  App: {
    getInfo: vi.fn(async () => ({
      version: '1.0.0',
      name: 'CrowdSec Manager',
      id: 'com.crowdsec.manager.mobile',
      build: '1',
    })),
  },
}));

const capacitorPrefsStore = new Map<string, string>();
vi.mock('@capacitor/preferences', () => ({
  Preferences: {
    get: vi.fn(async ({ key }: { key: string }) => ({
      value: capacitorPrefsStore.has(key) ? capacitorPrefsStore.get(key)! : null,
    })),
    set: vi.fn(async ({ key, value }: { key: string; value: string }) => {
      capacitorPrefsStore.set(key, value);
    }),
    remove: vi.fn(async ({ key }: { key: string }) => {
      capacitorPrefsStore.delete(key);
    }),
  },
}));

afterEach(async () => {
  cleanup();
  vi.restoreAllMocks();
  // Reset Capacitor mock defaults that vi.restoreAllMocks doesn't reach.
  const { Capacitor } = await import('@capacitor/core');
  const { App: CapApp } = await import('@capacitor/app');
  vi.mocked(Capacitor.isNativePlatform).mockReturnValue(false);
  vi.mocked(Capacitor.getPlatform).mockReturnValue('web');
  vi.mocked(CapApp.getInfo).mockResolvedValue({
    version: '1.0.0',
    name: 'CrowdSec Manager',
    id: 'com.crowdsec.manager.mobile',
    build: '1',
  });
  capacitorPrefsStore.clear();
  window.localStorage.clear();
  document.body.removeAttribute('data-scroll-locked');
  document.body.removeAttribute('style');
});

const storage = new Map<string, string>();

Object.defineProperty(window, 'localStorage', {
  writable: true,
  value: {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => {
      storage.set(key, value);
    },
    removeItem: (key: string) => {
      storage.delete(key);
    },
    clear: () => {
      storage.clear();
    },
  },
});

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => {},
  }),
});

class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}

if (!globalThis.ResizeObserver) {
  globalThis.ResizeObserver =
    ResizeObserverMock as unknown as typeof ResizeObserver;
}

if (!globalThis.requestAnimationFrame) {
  globalThis.requestAnimationFrame = (callback: FrameRequestCallback) => {
    callback(0);
    return 0;
  };
}

if (!globalThis.cancelAnimationFrame) {
  globalThis.cancelAnimationFrame = () => {};
}

Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', {
  writable: true,
  value: () => ({
    clearRect: () => {},
    fillRect: () => {},
    getImageData: () => ({ data: new Uint8ClampedArray(4) }),
    putImageData: () => {},
    createImageData: () => ({ data: new Uint8ClampedArray(4) }),
    setTransform: () => {},
    drawImage: () => {},
    save: () => {},
    restore: () => {},
    beginPath: () => {},
    moveTo: () => {},
    lineTo: () => {},
    closePath: () => {},
    stroke: () => {},
    translate: () => {},
    scale: () => {},
    rotate: () => {},
    arc: () => {},
    fill: () => {},
    measureText: () => ({ width: 0 }),
    transform: () => {},
    rect: () => {},
    clip: () => {},
  }),
});

if (!globalThis.btoa) {
  globalThis.btoa = (value: string) =>
    Buffer.from(value, 'utf8').toString('base64');
}
