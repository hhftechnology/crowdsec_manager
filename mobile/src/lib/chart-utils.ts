/**
 * Chart utility constants for the mobile log dashboards. Mobile does not
 * define `--chart-*` CSS variables, so we map to the existing accent /
 * primary palette to stay consistent with the rest of the UI.
 */

export const CHART_COLORS = [
  'hsl(var(--primary))',
  'hsl(var(--accent-teal))',
  'hsl(var(--accent-amber))',
  'hsl(var(--success))',
  'hsl(var(--error, 0 65% 51%))',
] as const
