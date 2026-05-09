import type { QueryClient } from '@tanstack/react-query';

const decisionAndAlertKeys = [
  ['decisions'],
  ['decisions-analysis'],
  ['alerts-analysis'],
  ['alerts-geo-enrichment'],
  ['decision-history'],
  ['decision-history-analysis'],
  ['alert-history'],
  ['repeated-offenders'],
  ['history-activity'],
  ['crowdsec-metrics'],
] as const;

export function invalidateDecisionsAndAlerts(queryClient: QueryClient) {
  return Promise.all(
    decisionAndAlertKeys.map((queryKey) =>
      queryClient.invalidateQueries({ queryKey }),
    ),
  );
}
