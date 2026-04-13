import { Shield, AlertTriangle } from 'lucide-react';
import { MetricCard } from '@/components/MetricCard';

interface SecurityOverviewPanelProps {
  decisionsTotal: number;
  alertsCount: number;
  topScenarios?: Record<string, number>;
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

export function SecurityOverviewPanel({ decisionsTotal, alertsCount, topScenarios }: SecurityOverviewPanelProps) {
  const sortedScenarios = topScenarios
    ? Object.entries(topScenarios)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
    : [];

  return (
    <div className="rounded-xl border border-border bg-card p-4 space-y-4">
      <h3 className="text-sm font-semibold">Security Overview</h3>

      <div className="grid grid-cols-2 gap-3">
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
        <div className="space-y-2">
          <h4 className="text-xs font-medium text-muted-foreground">Top Scenarios</h4>
          <div className="space-y-1.5">
            {sortedScenarios.map(([scenario, count], index) => (
              <div key={scenario} className="flex items-center gap-2">
                <span className="text-[10px] font-mono text-muted-foreground w-4 shrink-0">
                  {index + 1}.
                </span>
                <span className="text-xs truncate flex-1">{scenario}</span>
                <span className="text-xs font-mono font-medium tabular-nums shrink-0">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
