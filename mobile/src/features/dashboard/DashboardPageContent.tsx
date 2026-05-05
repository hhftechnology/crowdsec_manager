import { useCallback, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { RefreshCw } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { PageHeader } from '@/components/PageHeader';
import { PullToRefresh } from '@/components/PullToRefresh';
import { QueryStateView } from '@/components/QueryStateView';
import { DashboardSkeleton } from '@/components/dashboard/DashboardSkeleton';
import { Bars, Donut, Dot, Pill, Spike, TextLink, UpperBadge } from '@/components/design';
import { normalizeAppError, type AppErrorState } from '@/lib/errors';
import { relativeTime } from '@/lib/utils';
import type {
  CrowdsecHealth,
  CrowdsecAlert,
  DiagnosticResult,
  HealthContainer,
  HistoryActivityBucket,
  StackHealth,
  AlertsResponse,
} from '@/lib/api';

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
  const [decisionTypes, setDecisionTypes] = useState<Record<string, number>>({});
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchData = useCallback(async () => {
    if (!api) return;
    setLoading(true);
    setError(null);

    const [stackRes, crowdsecRes, completeRes, publicRes, alertsRes, decisionsSummaryRes, activityRes] =
      await Promise.allSettled([
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

    if (stackRes.status === 'fulfilled') setStack(stackRes.value);
    if (crowdsecRes.status === 'fulfilled') setCrowdsec(crowdsecRes.value);
    if (completeRes.status === 'fulfilled') setComplete(completeRes.value);

    if (decisionsSummaryRes.status === 'fulfilled' && decisionsSummaryRes.value) {
      setDecisionsTotal(decisionsSummaryRes.value.count);
      const types = (decisionsSummaryRes.value as { by_type?: Record<string, number> }).by_type ?? {};
      setDecisionTypes(types);
    } else if (completeRes.status === 'fulfilled' && Array.isArray(completeRes.value.decisions)) {
      setDecisionsTotal(completeRes.value.decisions.length);
      const types: Record<string, number> = {};
      for (const d of completeRes.value.decisions) {
        const t = (d.type ?? 'ban').toLowerCase();
        types[t] = (types[t] ?? 0) + 1;
      }
      setDecisionTypes(types);
    } else {
      setDecisionsTotal(0);
      setDecisionTypes({});
    }

    if (activityRes.status === 'fulfilled' && activityRes.value) {
      setActivityBuckets(activityRes.value.buckets ?? []);
    } else {
      setActivityBuckets([]);
    }

    if (publicRes.status === 'fulfilled') setPublicIP(publicRes.value?.ip || '');

    if (alertsRes.status === 'fulfilled' && alertsRes.value && 'alerts' in alertsRes.value) {
      const ar = alertsRes.value as AlertsResponse;
      setAlertsCount(ar.count ?? ar.alerts?.length ?? 0);
      setRecentAlerts(ar.alerts ?? []);

      const scenarioMap: Record<string, number> = {};
      for (const alert of ar.alerts ?? []) {
        if (alert.scenario) scenarioMap[alert.scenario] = (scenarioMap[alert.scenario] ?? 0) + 1;
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
      if (publicRes.status !== 'fulfilled') setPublicIP('');
    }
    setLoading(false);
  }, [api]);

  useMountEffect(() => {
    fetchData();
  });

  const containers = stack?.containers ?? [];
  const runningCount = containers.filter((c) => c.running).length;

  const knownBans = decisionTypes['ban'] ?? 0;
  const captchas = decisionTypes['captcha'] ?? 0;
  const whitelisted = decisionTypes['whitelist'] ?? decisionTypes['allow'] ?? 0;
  const categorized = knownBans + captchas + whitelisted;
  const bans = categorized === 0 && decisionsTotal > 0 ? decisionsTotal : knownBans;

  const trafficBars = activityBuckets.length
    ? activityBuckets.slice(-16).map((b) => (b.decisions ?? 0) + (b.alerts ?? 0))
    : [];

  const lastBuckets = activityBuckets.slice(-2);
  const prevTotal = lastBuckets[0] ? (lastBuckets[0].decisions ?? 0) + (lastBuckets[0].alerts ?? 0) : 0;
  const currTotal = lastBuckets[1] ? (lastBuckets[1].decisions ?? 0) + (lastBuckets[1].alerts ?? 0) : 0;
  const trafficDelta =
    lastBuckets.length === 2 && prevTotal > 0
      ? Math.round(((currTotal - prevTotal) / prevTotal) * 100)
      : null;

  const topScenarioEntries = Object.entries(topScenarios)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 3);

  return (
    <PullToRefresh onRefresh={fetchData}>
      <div className="pb-nav bg-canvas">
        <div className="px-md pt-md flex items-center justify-between">
          <Pill tone={crowdsec?.status === 'healthy' ? 'success' : 'warning'}>
            <Dot tone={crowdsec?.status === 'healthy' ? 'success' : 'warning'} pulse /> {crowdsec?.status ?? 'checking'}
          </Pill>
          <button
            onClick={fetchData}
            disabled={loading}
            aria-label="Refresh"
            className="w-9 h-9 rounded-pill border border-hairline bg-canvas inline-flex items-center justify-center text-ink hover:bg-surface-soft transition-colors disabled:opacity-50"
          >
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
          </button>
        </div>

        <PageHeader
          eyebrow="Overview"
          title="Today, calm."
          subtitle={`${runningCount}/${containers.length || 0} containers up · ${decisionsTotal} active decisions · ${alertsCount} alerts in the last 7d`}
        />

        <div className="px-md pb-md space-y-md">
          <QueryStateView
            isLoading={loading}
            error={error}
            loadingFallback={<DashboardSkeleton />}
            onRetry={fetchData}
            isEmpty={!stack && !crowdsec && !complete}
            emptyTitle="No dashboard data"
            emptyDescription="Connect to the API and refresh to load health information."
          >
            {/* Hero coral band — public IP + sparkline */}
            <div className="rounded-lg bg-primary text-on-primary p-lg">
              <div className="flex items-start justify-between gap-md">
                <div className="min-w-0">
                  <div className="text-caption-uppercase uppercase opacity-80">Public IP · seen by edge</div>
                  <div className="font-display text-display-sm mt-xxs font-mono truncate">{publicIP || '—'}</div>
                </div>
                <UpperBadge tone="cream">Stable</UpperBadge>
              </div>
              <div className="mt-md flex items-end gap-md">
                <Bars values={trafficBars} tone="dark" height={48} />
                <div className="ml-auto text-right shrink-0">
                  <div className="text-caption-uppercase uppercase opacity-80">Last 24h</div>
                  <div className="font-display text-display-sm">
                    {trafficDelta === null ? `${decisionsTotal}` : `${trafficDelta >= 0 ? '+' : ''}${trafficDelta}%`}
                  </div>
                </div>
              </div>
            </div>

            {/* 2x2 stat grid */}
            <div className="grid grid-cols-2 gap-sm">
              <StatBlock
                label="CrowdSec"
                value={crowdsec?.status ?? '—'}
                sub={`bouncers · ${complete?.bouncers?.length ?? 0}`}
                tone={crowdsec?.status === 'healthy' ? 'success' : 'warn'}
              />
              <StatBlock
                label="Containers"
                value={`${runningCount} / ${containers.length || 0}`}
                sub={stack?.allRunning ? 'all running' : 'degraded'}
                tone={stack?.allRunning ? 'success' : 'warn'}
              />
              <StatBlock label="Decisions" value={String(decisionsTotal)} sub="active" tone="ink" />
              <StatBlock label="Alerts" value={String(alertsCount)} sub="last 7d" tone={alertsCount > 0 ? 'warn' : 'ink'} />
            </div>

            {/* Security overview */}
            <div className="rounded-lg bg-surface-card text-ink p-lg dark:bg-surface-dark dark:text-on-dark">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-xs">
                  <Spike className="w-3 h-3 text-ink dark:text-on-dark" />
                  <span className="text-caption-uppercase uppercase text-muted dark:text-on-dark-soft">security overview</span>
                </div>
                <span className="text-caption text-muted dark:text-on-dark-soft">24h</span>
              </div>
              <div className="mt-md grid grid-cols-[auto_1fr] gap-md items-center">
                <Donut
                  size={96}
                  segments={[
                    { value: bans, color: 'primary' },
                    { value: captchas, color: 'accent-amber' },
                    { value: whitelisted, color: 'accent-teal' },
                  ]}
                />
                <div className="space-y-sm">
                  <LegendRow color="primary" label="Bans" value={bans} />
                  <LegendRow color="accent-amber" label="Captchas" value={captchas} />
                  <LegendRow color="accent-teal" label="Whitelisted" value={whitelisted} />
                </div>
              </div>
              {topScenarioEntries.length > 0 && (
                <div className="mt-md rounded-md bg-surface-soft p-sm dark:bg-surface-dark-soft">
                  <div className="flex items-center justify-between text-caption text-muted dark:text-on-dark-soft">
                    <span>Top scenario</span>
                    <span>events</span>
                  </div>
                  <div className="mt-xs space-y-xs font-mono text-code">
                    {topScenarioEntries.map(([name, count]) => (
                      <div key={name} className="flex items-center justify-between text-ink gap-sm dark:text-on-dark">
                        <span className="truncate text-muted dark:text-on-dark-soft">{name}</span>
                        <span className="shrink-0">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Containers — cream feature card */}
            {stack && (
              <div className="rounded-lg bg-surface-card p-md">
                <div className="flex items-center justify-between mb-sm">
                  <span className="font-display text-title-md text-ink">Containers</span>
                  <UpperBadge tone="cream">{stack.allRunning ? 'All running' : 'Degraded'}</UpperBadge>
                </div>
                <div className="space-y-xs">
                  {containers.map((c: HealthContainer) => (
                    <ContainerRow key={c.id || c.name} name={c.name} id={c.id?.slice(0, 12) ?? ''} running={c.running} status={c.status} />
                  ))}
                </div>
              </div>
            )}

            {/* Recent activity */}
            <div className="rounded-lg bg-canvas border border-hairline p-md">
              <div className="flex items-center justify-between mb-sm">
                <span className="font-display text-title-md text-ink">Recent activity</span>
                <TextLink onClick={() => undefined}>View all</TextLink>
              </div>
              {recentAlerts.length === 0 ? (
                <p className="text-body-sm text-muted">No recent alerts.</p>
              ) : (
                <div className="divide-y divide-hairline-soft">
                  {recentAlerts.slice(0, 5).map((alert, i) => (
                    <ActivityRow
                      key={alert.id ?? i}
                      scenario={alert.scenario || 'alert'}
                      ip={alert.value || alert.source?.ip || '—'}
                      time={alert.start_at ? relativeTime(alert.start_at) : '—'}
                      tone={alert.scenario?.includes('http') ? 'error' : 'warning'}
                    />
                  ))}
                </div>
              )}
            </div>

            {lastUpdated && (
              <p className="text-caption text-muted-soft text-center">
                Last updated · {lastUpdated.toLocaleTimeString()} · {lastUpdated.toDateString()}
              </p>
            )}
          </QueryStateView>
        </div>
      </div>
    </PullToRefresh>
  );
}

function StatBlock({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: string;
  sub: string;
  tone: 'success' | 'warn' | 'ink';
}) {
  const toneClass = tone === 'success' ? 'text-success' : tone === 'warn' ? 'text-warning' : 'text-ink';
  return (
    <div className="rounded-lg bg-surface-card p-md">
      <div className="text-caption-uppercase uppercase text-muted">{label}</div>
      <div className={`mt-xxs font-display text-display-sm capitalize ${toneClass}`}>{value}</div>
      <div className="text-caption text-muted-soft mt-xxs">{sub}</div>
    </div>
  );
}

function LegendRow({ color, label, value }: { color: 'primary' | 'accent-amber' | 'accent-teal'; label: string; value: number }) {
  const colorClass = {
    primary: 'bg-primary',
    'accent-amber': 'bg-accent-amber',
    'accent-teal': 'bg-accent-teal',
  }[color];

  return (
    <div className="flex items-center justify-between text-body-sm">
      <span className="flex items-center gap-xs">
        <span className={`w-2.5 h-2.5 rounded-xs ${colorClass}`} />
        <span className="text-ink dark:text-on-dark">{label}</span>
      </span>
      <span className="text-ink font-mono dark:text-on-dark">{value}</span>
    </div>
  );
}

function ContainerRow({ name, id, running, status }: { name: string; id: string; running: boolean; status?: string }) {
  return (
    <div className="flex items-center gap-sm py-xs">
      <Dot tone={running ? 'success' : 'error'} />
      <div className="min-w-0 flex-1">
        <div className="text-body-sm font-medium text-ink truncate">{name}</div>
        <div className="text-caption font-mono text-muted-soft truncate">{id}</div>
      </div>
      <Pill tone={running ? 'success' : 'error'}>{status || (running ? 'running' : 'stopped')}</Pill>
    </div>
  );
}

function ActivityRow({ scenario, ip, time, tone }: { scenario: string; ip: string; time: string; tone: 'error' | 'warning' | 'muted' }) {
  return (
    <div className="flex items-center gap-sm py-sm">
      <Dot tone={tone === 'muted' ? 'muted' : tone} />
      <div className="min-w-0 flex-1">
        <div className="text-body-sm text-ink truncate">{scenario}</div>
        <div className="text-caption font-mono text-muted">{ip}</div>
      </div>
      <span className="text-caption text-muted-soft shrink-0">{time}</span>
    </div>
  );
}
