import { useCallback, useState, type ComponentType } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { RefreshCw, Activity, ShieldCheck, Globe, Server } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { PageHeader } from '@/components/PageHeader';
import { PullToRefresh } from '@/components/PullToRefresh';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { QueryStateView } from '@/components/QueryStateView';
import { StatusDot } from '@/components/StatusDot';
import { StatusRow } from '@/components/StatusRow';
import { MetricCard } from '@/components/MetricCard';
import { DashboardSkeleton } from '@/components/dashboard/DashboardSkeleton';
import { SecurityOverviewPanel } from '@/components/dashboard/SecurityOverviewPanel';
import { RecentActivityPanel } from '@/components/dashboard/RecentActivityPanel';
import { normalizeAppError, type AppErrorState } from '@/lib/errors';
import type { CrowdsecHealth, CrowdsecAlert, DiagnosticResult, HealthContainer, HistoryActivityBucket, StackHealth, Bouncer, HealthCheckItem, AlertsResponse } from '@/lib/api';

export default function DashboardPage() {
  const { api } = useApi();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<AppErrorState | null>(null);
  const [stack, setStack] = useState<StackHealth | null>(null);
  const [crowdsec, setCrowdsec] = useState<CrowdsecHealth | null>(null);
  const [complete, setComplete] = useState<DiagnosticResult | null>(null);
  const [publicIP, setPublicIP] = useState('');
  const [decisionsTotal, setDecisionsTotal] = useState(0);
  const [alertsCount, setAlertsCount] = useState(0);
  const [topScenarios, setTopScenarios] = useState<Record<string, number>>({});
  const [recentAlerts, setRecentAlerts] = useState<CrowdsecAlert[]>([]);
  const [activityBuckets, setActivityBuckets] = useState<HistoryActivityBucket[]>([]);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchData = useCallback(async () => {
    if (!api) return;
    setLoading(true);
    setError(null);

    const [stackRes, crowdsecRes, completeRes, publicRes, alertsRes, decisionsSummaryRes, activityRes] = await Promise.allSettled([
        api.health.getStack(),
        api.health.getCrowdsec(),
        api.health.getComplete(),
        api.ip.getPublicIP(),
        api.crowdsec.alertsAnalysis({ since: '7d' }).catch(() => null),
        api.crowdsec.decisionsSummary().catch(() => null),
        api.crowdsec.historyActivity({ window: '24h', bucket: 'hour' }).catch(() => null),
      ]);

    const criticalResults = [stackRes, crowdsecRes, completeRes];
    const firstCriticalError = criticalResults.find(
      (result): result is PromiseRejectedResult => result.status === 'rejected',
    );

    if (stackRes.status === 'fulfilled') {
      setStack(stackRes.value);
    }

    if (crowdsecRes.status === 'fulfilled') {
      setCrowdsec(crowdsecRes.value);
    }

    if (completeRes.status === 'fulfilled') {
      setComplete(completeRes.value);
    }

    if (decisionsSummaryRes.status === 'fulfilled' && decisionsSummaryRes.value) {
      setDecisionsTotal(decisionsSummaryRes.value.count);
    }

    if (activityRes.status === 'fulfilled' && activityRes.value) {
      setActivityBuckets(activityRes.value.buckets ?? []);
    }

    if (publicRes.status === 'fulfilled') {
      setPublicIP(publicRes.value?.ip || '');
    }

    if (alertsRes.status === 'fulfilled' && alertsRes.value && 'alerts' in alertsRes.value) {
      const ar = alertsRes.value as AlertsResponse;
      setAlertsCount(ar.count ?? ar.alerts?.length ?? 0);
      setRecentAlerts(ar.alerts ?? []);

      const scenarioMap: Record<string, number> = {};
      for (const alert of ar.alerts ?? []) {
        if (alert.scenario) {
          scenarioMap[alert.scenario] = (scenarioMap[alert.scenario] ?? 0) + 1;
        }
      }
      setTopScenarios(scenarioMap);
    }

    if (criticalResults.every((result) => result.status === 'rejected')) {
      setError(
        normalizeAppError(firstCriticalError?.reason, {
          fallbackMessage: 'Failed to load dashboard data.',
        }),
      );
    } else {
      setError(null);
      setLastUpdated(new Date());
      if (alertsRes.status !== 'fulfilled' || !alertsRes.value || !('alerts' in alertsRes.value)) {
        setAlertsCount(0);
        setRecentAlerts([]);
        setTopScenarios({});
      }
      if (publicRes.status !== 'fulfilled') {
        setPublicIP('');
      }
    }
    setLoading(false);
  }, [api]);

  useMountEffect(() => {
    fetchData();
  });

  const completeBouncers = complete?.bouncers ?? [];

  return (
    <PullToRefresh onRefresh={fetchData}>
      <div className="pb-nav">
        <PageHeader
          title="Dashboard"
          subtitle="Health and runtime overview"
          action={
            <Button variant="ghost" size="icon" onClick={fetchData} disabled={loading}>
              <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
            </Button>
          }
        />

        <div className="px-4 space-y-4">
          <QueryStateView
            isLoading={loading}
            error={error}
            loadingFallback={<DashboardSkeleton />}
            onRetry={fetchData}
            isEmpty={!stack && !crowdsec && !complete}
            emptyTitle="No dashboard data"
            emptyDescription="Connect to the API and refresh to load health information."
          >
            {/* Top stat cards */}
            <div className="grid grid-cols-2 gap-3">
              <StatCard icon={Globe} title="Public IP" value={publicIP || '—'} />
              <StatCard
                icon={ShieldCheck}
                title="CrowdSec"
                value={crowdsec?.status || 'unknown'}
                tone={crowdsec?.status === 'healthy' ? 'ok' : 'warn'}
              />
              <StatCard
                icon={Activity}
                title="Containers"
                value={stack ? `${stack.containers.filter((c) => c.running).length}/${stack.containers.length}` : '—'}
                tone={stack?.allRunning ? 'ok' : 'warn'}
              />
              <StatCard
                icon={Server}
                title="Bouncers"
                value={complete ? String(completeBouncers.length) : '—'}
                tone={complete && completeBouncers.length > 0 ? 'ok' : 'warn'}
              />
            </div>

            {/* Security Overview */}
            <SecurityOverviewPanel
              decisionsTotal={decisionsTotal}
              alertsCount={alertsCount}
              topScenarios={topScenarios}
              activityBuckets={activityBuckets}
            />

            {/* Stack Health — Container Status */}
            {stack && <ContainerStatusPanel stack={stack} />}

            {/* Recent Activity */}
            <RecentActivityPanel alerts={recentAlerts} />

            {/* CrowdSec Health Checks */}
            {crowdsec && <HealthChecksPanel crowdsec={crowdsec} />}

            {/* Diagnostics Summary */}
            {complete && <DiagnosticsSummaryPanel diagnostics={complete} />}

            {/* Last updated timestamp */}
            {lastUpdated && (
              <p className="text-[10px] text-muted-foreground text-center">
                Last updated: {lastUpdated.toLocaleString()}
              </p>
            )}
          </QueryStateView>
        </div>
      </div>
    </PullToRefresh>
  );
}

/* ────────────────────────── Container Status Panel ────────────────────────── */

function ContainerStatusPanel({ stack }: { stack: StackHealth }) {
  return (
    <div className="rounded-xl border border-border bg-card p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">Containers</h3>
        <Badge variant={stack.allRunning ? 'success' : 'warning'}>
          {stack.allRunning ? 'All Running' : 'Degraded'}
        </Badge>
      </div>
      <div className="space-y-1">
        {stack.containers.map((container: HealthContainer) => (
          <div key={container.id || container.name} className="flex items-center gap-2 py-1.5">
            <StatusDot color={container.running ? 'success' : 'error'} />
            <div className="min-w-0 flex-1">
              <div className="text-xs font-medium truncate">{container.name}</div>
              <div className="text-[10px] text-muted-foreground font-mono truncate">{container.id?.slice(0, 12)}</div>
            </div>
            <Badge variant={container.running ? 'success' : 'destructive'} className="text-[10px] shrink-0">
              {container.status || (container.running ? 'running' : 'stopped')}
            </Badge>
          </div>
        ))}
      </div>
      {stack.timestamp && (
        <p className="text-[10px] text-muted-foreground">Updated: {new Date(stack.timestamp).toLocaleString()}</p>
      )}
    </div>
  );
}

/* ────────────────────────── Health Checks Panel ────────────────────────── */

function HealthChecksPanel({ crowdsec }: { crowdsec: CrowdsecHealth }) {
  const checks = crowdsec.checks ? Object.entries(crowdsec.checks) : [];

  return (
    <div className="rounded-xl border border-border bg-card p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">CrowdSec Health</h3>
        <Badge variant={crowdsec.status === 'healthy' ? 'success' : crowdsec.status === 'degraded' ? 'warning' : 'outline'}>
          {crowdsec.status || 'unknown'}
        </Badge>
      </div>

      {checks.length > 0 ? (
        <div className="space-y-2">
          {checks.map(([name, check]: [string, HealthCheckItem]) => (
            <div key={name}>
              <div className="flex items-center justify-between py-1">
                <div className="flex items-center gap-2">
                  <StatusDot color={check.status === 'ok' || check.status === 'pass' ? 'success' : check.status === 'warn' ? 'warning' : 'error'} />
                  <span className="text-xs font-medium">{name}</span>
                </div>
                <span className="text-xs text-muted-foreground truncate max-w-[50%] text-right">{check.message}</span>
              </div>
              {check.error && (
                <p className="text-[10px] text-red-500 dark:text-red-400 ml-4 mt-0.5">{check.error}</p>
              )}
            </div>
          ))}
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">No individual health checks reported.</p>
      )}

      {crowdsec.timestamp && (
        <p className="text-[10px] text-muted-foreground">Updated: {new Date(crowdsec.timestamp).toLocaleString()}</p>
      )}
    </div>
  );
}

/* ────────────────────────── Diagnostics Summary Panel ────────────────────────── */

function DiagnosticsSummaryPanel({ diagnostics }: { diagnostics: DiagnosticResult }) {
  const bouncers = diagnostics.bouncers ?? [];
  const decisions = diagnostics.decisions ?? [];

  return (
    <div className="rounded-xl border border-border bg-card p-4 space-y-3">
      <h3 className="text-sm font-semibold">Diagnostics Summary</h3>

      <div className="grid grid-cols-2 gap-2">
        <MetricCard
          label="Bouncers"
          value={bouncers.length}
          variant={bouncers.length > 0 ? 'success' : 'warning'}
        />
        <MetricCard
          label="Decisions"
          value={decisions.length}
          variant="default"
        />
      </div>

      {/* Bouncers mini-list */}
      {bouncers.length > 0 && (
        <div className="space-y-1">
          <h4 className="text-xs font-medium text-muted-foreground">Active Bouncers</h4>
          {bouncers.slice(0, 5).map((bouncer: Bouncer) => (
            <div key={bouncer.name} className="flex items-center justify-between py-1">
              <div className="flex items-center gap-2 min-w-0">
                <StatusDot color={bouncer.valid ? 'success' : 'error'} />
                <span className="text-xs truncate">{bouncer.name}</span>
              </div>
              <span className="text-[10px] text-muted-foreground font-mono shrink-0">{bouncer.ip_address}</span>
            </div>
          ))}
          {bouncers.length > 5 && (
            <p className="text-[10px] text-muted-foreground">+{bouncers.length - 5} more</p>
          )}
        </div>
      )}

      {/* Traefik integration status */}
      {diagnostics.traefik_integration && (
        <>
          <Separator />
          <StatusRow label="Traefik Integration" value="Configured" status="success" />
        </>
      )}

      <Separator />
      <StatusRow label="Timestamp" value={new Date(diagnostics.timestamp).toLocaleString()} />
    </div>
  );
}

/* ────────────────────────── Stat Card ────────────────────────── */

type StatBorderVariant = 'success' | 'warning' | 'destructive';

const statBorderClasses: Record<StatBorderVariant, string> = {
  success: 'border-l-4 border-l-emerald-500',
  warning: 'border-l-4 border-l-amber-500',
  destructive: 'border-l-4 border-l-red-500',
};

function StatCard({
  icon: Icon,
  title,
  value,
  tone = 'neutral',
  borderVariant,
}: {
  icon: ComponentType<{ className?: string }>;
  title: string;
  value: string;
  tone?: 'neutral' | 'ok' | 'warn';
  borderVariant?: StatBorderVariant;
}) {
  const toneClass = tone === 'ok' ? 'text-success' : tone === 'warn' ? 'text-warning' : 'text-foreground';

  return (
    <div className={`rounded-xl border border-border bg-card p-3 ${borderVariant ? statBorderClasses[borderVariant] : ''}`}>
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Icon className="h-3.5 w-3.5" />
        {title}
      </div>
      <div className={`mt-1 text-sm font-semibold ${toneClass}`}>{value}</div>
    </div>
  );
}
