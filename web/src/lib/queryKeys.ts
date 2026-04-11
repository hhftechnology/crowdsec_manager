// Centralised query key constants for TanStack React Query.
// Using `as const` tuples ensures type-safe cache invalidation and avoids
// key typos across pages and hooks.

export const queryKeys = {
  health: ['health'] as const,
  decisions: ['decisions'] as const,
  decisionsAnalysis: ['decisions-analysis'] as const,
  bouncers: ['bouncers'] as const,
  alerts: ['alerts'] as const,
  alertsAnalysis: ['alerts-analysis'] as const,
  alertsDashboard: ['alerts', 'dashboard'] as const,
  diagnostics: ['diagnostics'] as const,
  allowlists: ['allowlists'] as const,
  allowlistInspect: ['allowlist-inspect'] as const,
  services: ['services'] as const,
  scenarios: ['scenarios'] as const,
  crowdsecHealth: ['crowdsec-health'] as const,
  logsCrowdsec: ['logs-crowdsec'] as const,
  stackHealth: ['stack-health'] as const,
} as const

// Standard polling intervals (ms) shared across all pages.
export const refetchIntervals = {
  /** Health checks, container status — fast feedback loop. */
  fast: 5000,
  /** Decisions, bouncers, services — moderate refresh. */
  normal: 15000,
  /** Alerts, less critical data — conservative. */
  slow: 30000,
} as const
