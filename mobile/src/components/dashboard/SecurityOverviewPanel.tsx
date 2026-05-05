import { Shield, AlertTriangle } from 'lucide-react';
import { MetricCard } from '@/components/MetricCard';
import type { HistoryActivityBucket } from '@/lib/api';

interface SecurityOverviewPanelProps {
  decisionsTotal: number;
  alertsCount: number;
  topScenarios?: Record<string, number>;
  activityBuckets?: HistoryActivityBucket[];
}

function decisionsBorderVariant(count: number) {
  if (count >= 50) return 'destructive' as const;
  if (count >= 10) return 'warning' as const;
  return 'success' as const;
}

function alertsBorderVariant(count: number) {
  if (count >= 30) return 'destructive' as const;
  if (count >= 10) return 'warning' as const;
  return 'success' as const;
}

export function SecurityOverviewPanel({ decisionsTotal, alertsCount, topScenarios, activityBuckets }: SecurityOverviewPanelProps) {
  const sortedScenarios = topScenarios
    ? Object.entries(topScenarios)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
    : [];

  const activity24hAlerts = activityBuckets?.reduce((sum, b) => sum + b.alerts, 0) ?? 0;
  const activity24hDecisions = activityBuckets?.reduce((sum, b) => sum + b.decisions, 0) ?? 0;
  const hasActivity = activityBuckets && activityBuckets.length > 0;

  return (
    <div className="rounded-lg border border-hairline bg-surface-card p-md space-y-md">
      <h3 className="text-title-sm font-semibold text-ink">Security Overview</h3>

      <div className="grid grid-cols-2 gap-sm">
        <MetricCard
          label="Active Decisions"
          value={decisionsTotal}
          icon={Shield}
          borderVariant={decisionsBorderVariant(decisionsTotal)}
        />
        <MetricCard
          label="Alerts 7d"
          value={alertsCount}
          icon={AlertTriangle}
          borderVariant={alertsBorderVariant(alertsCount)}
        />
      </div>

      {sortedScenarios.length > 0 && (
        <div className="space-y-xs">
          <h4 className="text-caption font-medium text-muted">Top Scenarios</h4>
          <div className="space-y-1.5">
            {sortedScenarios.map(([scenario, count], index) => (
              <div key={scenario} className="flex items-center gap-xs">
                <span className="text-caption font-mono text-muted w-4 shrink-0">
                  {index + 1}.
                </span>
                <span className="text-caption truncate flex-1 text-ink">{scenario}</span>
                <span className="text-caption font-mono font-medium tabular-nums shrink-0 text-ink">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {hasActivity && (
        <div className="space-y-xs">
          <h4 className="text-caption font-medium text-muted">Recent Activity</h4>
          <div className="grid grid-cols-2 gap-xs">
            <MetricCard label="Alerts" value={activity24hAlerts} variant="default" />
            <MetricCard label="Decisions" value={activity24hDecisions} variant="default" />
          </div>
        </div>
      )}
    </div>
  );
}
