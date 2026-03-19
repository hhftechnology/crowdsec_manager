import { useEffect, type EffectCallback } from 'react';

/**
 * Executes a side effect once on mount. Direct useEffect is banned in this codebase.
 *
 * Good: DOM setup, third-party widget init, browser API subscriptions (ResizeObserver, etc.)
 * Bad: data fetching (use React Query), deriving state (compute inline), event responses (use handlers)
 *
 * @param effect - Imperative function that runs on mount. May return a cleanup function.
 */
export function useMountEffect(effect: EffectCallback): void {
  useEffect(effect, []); // eslint-disable-line react-hooks/exhaustive-deps
}
