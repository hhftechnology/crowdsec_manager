/**
 * @deprecated Import from '@/lib/api/index' or specific domain clients instead.
 * This file re-exports everything from the new modular API client structure
 * for backward compatibility. All existing imports continue to work.
 *
 * New code should import from specific domain files:
 *   import { healthAPI } from '@/lib/api/health'
 *   import { proxyAPI } from '@/lib/api/proxy'
 */
export * from './api/index'
export { default } from './api/index'
