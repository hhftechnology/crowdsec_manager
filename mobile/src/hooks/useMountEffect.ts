import { useEffect, type EffectCallback } from 'react';

/**
 * Executes a side effect once on mount. Direct useEffect is banned in my repo.
 *
 * Good: DOM setup, third-party init, browser API subscriptions
 * Bad: data fetching (use React Query), deriving state (compute inline), event responses (use handlers)
 *
 * @param effect - Imperative function that runs on mount. May return a cleanup function.
 */
export function useMountEffect(effect: EffectCallback): void {
  useEffect(effect, []);
}
