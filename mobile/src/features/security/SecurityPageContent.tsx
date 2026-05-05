import { useCallback, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { Search, Upload, ShieldBan, FileSearch, Shield, ShieldAlert, ShieldCheck, ShieldX, History, RotateCcw } from 'lucide-react';
import { relativeTime } from '@/lib/utils';
import { PageHeader } from '@/components/PageHeader';
import { useApi } from '@/contexts/ApiContext';
import { PullToRefresh } from '@/components/PullToRefresh';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { QueryStateView } from '@/components/QueryStateView';
import { ConfirmActionDialog } from '@/components/ConfirmActionDialog';
import { StatusRow } from '@/components/StatusRow';
import { MetricCard } from '@/components/MetricCard';
import { AddDecisionForm } from '@/components/security/AddDecisionForm';
import { DeleteDecisionForm } from '@/components/security/DeleteDecisionForm';
import { DecisionFilters } from '@/components/security/DecisionFilters';
import { AlertsListPanel } from '@/components/security/AlertsListPanel';
import { ButtonPrimary, ButtonSecondary, CategoryTab, FieldLabel, Pill, Dot, type PillTone } from '@/components/design';
import { showActionError, showActionSuccess } from '@/lib/actionToast';
import type { AddDecisionRequest, CrowdsecAlert, Decision, DecisionHistoryRecord, IPSecurity, IPBlockedStatus, MetricsResponse } from '@/lib/api';

/* ────────────────────── Local Types ────────────────────── */

interface DecisionsAnalysisData {
  total?: number;
  by_type?: Record<string, number>;
  by_origin?: Record<string, number>;
  by_scope?: Record<string, number>;
  recent?: Decision[];
  [key: string]: unknown;
}

interface AlertsAnalysisData {
  count?: number;
  alerts?: CrowdsecAlert[];
  by_scenario?: Record<string, number>;
  by_scope?: Record<string, number>;
  recent?: CrowdsecAlert[];
  [key: string]: unknown;
}

interface DecisionFilterState {
  type?: string;
  scope?: string;
  origin?: string;
}

const PAGE_SIZE = 20;

const TABS: Array<{ id: string; label: string }> = [
  { id: 'ip', label: 'IP' },
  { id: 'decisions', label: 'Decisions' },
  { id: 'history', label: 'History' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'metrics', label: 'Metrics' },
];

function decisionTone(type: string): PillTone {
  switch (type.toLowerCase()) {
    case 'ban': return 'coral';
    case 'captcha': return 'amber';
    default: return 'cream';
  }
}

export default function SecurityPage() {
  const { api } = useApi();
  const [loading, setLoading] = useState(true);
  const [initialLoaded, setInitialLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('ip');

  const [ipInput, setIpInput] = useState('');
  const [ipBlockedResult, setIPBlockedResult] = useState<IPBlockedStatus | null>(null);
  const [ipSecurityResult, setIPSecurityResult] = useState<IPSecurity | null>(null);
  const [unbanInput, setUnbanInput] = useState('');
  const [unbanTarget, setUnbanTarget] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [decisionsTotal, setDecisionsTotal] = useState(0);
  const [decisionPage, setDecisionPage] = useState(1);
  const [decisionAnalysis, setDecisionAnalysis] = useState<DecisionsAnalysisData | null>(null);
  const [decisionFilters, setDecisionFilters] = useState<DecisionFilterState>({});
  const [importFile, setImportFile] = useState<File | null>(null);

  const [decisionHistory, setDecisionHistory] = useState<DecisionHistoryRecord[]>([]);
  const [decisionHistoryTotal, setDecisionHistoryTotal] = useState(0);
  const [decisionHistoryPage, setDecisionHistoryPage] = useState(1);
  const [reapplyTarget, setReapplyTarget] = useState<DecisionHistoryRecord | null>(null);

  const [alertsAnalysis, setAlertsAnalysis] = useState<AlertsAnalysisData | null>(null);
  const [alertInspectId, setAlertInspectId] = useState('');
  const [inspectedAlert, setInspectedAlert] = useState<CrowdsecAlert | null>(null);
  const [alertDeleteId, setAlertDeleteId] = useState<number | null>(null);

  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);

  const buildDecisionAnalysis = useCallback((rows: Decision[], total: number): DecisionsAnalysisData => {
    const by_type: Record<string, number> = {};
    const by_origin: Record<string, number> = {};
    const by_scope: Record<string, number> = {};

    for (const decision of rows) {
      if (decision.type) by_type[decision.type] = (by_type[decision.type] ?? 0) + 1;
      if (decision.origin) by_origin[decision.origin] = (by_origin[decision.origin] ?? 0) + 1;
      if (decision.scope) by_scope[decision.scope] = (by_scope[decision.scope] ?? 0) + 1;
    }

    return { total, by_type, by_origin, by_scope, recent: rows };
  }, []);

  const loadSecurityData = useCallback(async ({
    nextDecisionFilters,
    nextDecisionPage,
    nextHistoryPage,
  }: {
    nextDecisionFilters?: DecisionFilterState;
    nextDecisionPage?: number;
    nextHistoryPage?: number;
  } = {}) => {
    if (!api) return;
    setLoading(true);
    setError(null);

    try {
      const resolvedDecisionFilters = nextDecisionFilters ?? decisionFilters;
      const resolvedDecisionPage = nextDecisionPage ?? decisionPage;
      const resolvedHistoryPage = nextHistoryPage ?? decisionHistoryPage;
      const decisionOffset = (resolvedDecisionPage - 1) * PAGE_SIZE;
      const historyOffset = (resolvedHistoryPage - 1) * PAGE_SIZE;
      const [decisionsRes, alertsRes, metricsRes, historyRes] = await Promise.all([
        api.crowdsec.decisionsAnalysis({
          ...resolvedDecisionFilters,
          limit: PAGE_SIZE,
          offset: decisionOffset,
        }),
        api.crowdsec.alertsAnalysis(),
        api.crowdsec.metrics(),
        api.crowdsec.decisionHistory({ limit: PAGE_SIZE, offset: historyOffset }),
      ]);

      setDecisions(decisionsRes?.decisions || []);
      setDecisionsTotal(decisionsRes?.total ?? decisionsRes?.count ?? decisionsRes?.decisions?.length ?? 0);
      setDecisionAnalysis(
        buildDecisionAnalysis(
          decisionsRes?.decisions || [],
          decisionsRes?.total ?? decisionsRes?.count ?? decisionsRes?.decisions?.length ?? 0,
        ),
      );
      setAlertsAnalysis(alertsRes as AlertsAnalysisData | null);
      setMetrics(metricsRes);
      setDecisionHistory(historyRes?.decisions || []);
      setDecisionHistoryTotal(historyRes?.total ?? historyRes?.count ?? historyRes?.decisions?.length ?? 0);

      const nextDecisionTotal = decisionsRes?.total ?? 0;
      const decisionPages = Math.max(1, Math.ceil(nextDecisionTotal / PAGE_SIZE));
      if (resolvedDecisionPage > decisionPages) {
        setDecisionPage(decisionPages);
        void loadSecurityData({
          nextDecisionFilters: resolvedDecisionFilters,
          nextDecisionPage: decisionPages,
          nextHistoryPage: resolvedHistoryPage,
        });
        return;
      }

      const nextHistoryTotal = historyRes?.total ?? 0;
      const historyPages = Math.max(1, Math.ceil(nextHistoryTotal / PAGE_SIZE));
      if (resolvedHistoryPage > historyPages) {
        setDecisionHistoryPage(historyPages);
        void loadSecurityData({
          nextDecisionFilters: resolvedDecisionFilters,
          nextDecisionPage: resolvedDecisionPage,
          nextHistoryPage: historyPages,
        });
        return;
      }
      setInitialLoaded(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load security data');
    } finally {
      setLoading(false);
    }
  }, [api, buildDecisionAnalysis, decisionFilters, decisionHistoryPage, decisionPage]);

  const fetchAll = useCallback(async () => {
    await loadSecurityData();
  }, [loadSecurityData]);

  useMountEffect(() => {
    void loadSecurityData();
  });

  const decisionCount = decisionsTotal;
  const alertCount = alertsAnalysis?.count ?? 0;
  const decisionPageCount = Math.max(1, Math.ceil(Math.max(decisionsTotal, 1) / PAGE_SIZE));
  const decisionHistoryPageCount = Math.max(1, Math.ceil(Math.max(decisionHistoryTotal, 1) / PAGE_SIZE));

  const checkIP = async () => {
    if (!api || !ipInput.trim()) return;
    setActionLoading(true);
    try {
      const [blocked, security] = await Promise.all([
        api.ip.checkBlocked(ipInput.trim()),
        api.ip.checkSecurity(ipInput.trim()),
      ]);
      setIPBlockedResult(blocked);
      setIPSecurityResult(security);
      showActionSuccess('IP check complete', ipInput.trim());
    } catch (err) {
      showActionError('Failed to check IP', err);
    } finally {
      setActionLoading(false);
    }
  };

  const addDecision = async (form: AddDecisionRequest) => {
    if (!api) return;
    setActionLoading(true);
    try {
      const res = await api.crowdsec.addDecision(form);
      showActionSuccess('Decision added', res.message || 'CrowdSec accepted the decision');
      await fetchAll();
    } catch (err) {
      showActionError('Failed to add decision', err);
    } finally {
      setActionLoading(false);
    }
  };

  const deleteDecisionByParams = async (params: { id?: string; value?: string }) => {
    if (!api) return;
    setActionLoading(true);
    try {
      const res = await api.crowdsec.deleteDecision(params);
      showActionSuccess('Decision deleted', res.message || params.id || params.value || 'done');
      await fetchAll();
    } catch (err) {
      showActionError('Failed to delete decision', err);
    } finally {
      setActionLoading(false);
    }
  };

  const importDecisions = async () => {
    if (!api || !importFile) return;
    setActionLoading(true);
    try {
      const res = await api.crowdsec.importDecisions(importFile);
      showActionSuccess('Decisions imported', res.message || importFile.name);
      setImportFile(null);
      await fetchAll();
    } catch (err) {
      showActionError('Failed to import decisions', err);
    } finally {
      setActionLoading(false);
    }
  };

  const inspectAlert = async (idOverride?: number) => {
    const id = idOverride ?? Number(alertInspectId.trim());
    if (!api || !id) return;
    setActionLoading(true);
    try {
      const found = await api.crowdsec.inspectAlert(id);
      setInspectedAlert(found);
      setAlertInspectId(String(id));
      showActionSuccess('Alert loaded', `#${id}`);
    } catch (err) {
      showActionError('Failed to inspect alert', err);
    } finally {
      setActionLoading(false);
    }
  };

  const deleteAlert = async () => {
    if (!api || !alertDeleteId) return;
    setActionLoading(true);
    try {
      const res = await api.crowdsec.deleteAlert(alertDeleteId);
      showActionSuccess('Alert deleted', res.message || `#${alertDeleteId}`);
      setAlertDeleteId(null);
      setInspectedAlert(null);
      await fetchAll();
    } catch (err) {
      showActionError('Failed to delete alert', err);
    } finally {
      setActionLoading(false);
    }
  };

  const confirmUnban = async () => {
    if (!api || !unbanTarget) return;
    setActionLoading(true);
    try {
      const res = await api.ip.unban(unbanTarget);
      showActionSuccess('IP unbanned', res.message || unbanTarget);
      setUnbanInput('');
      setUnbanTarget(null);
      await fetchAll();
    } catch (err) {
      showActionError('Failed to unban IP', err);
    } finally {
      setActionLoading(false);
    }
  };

  const confirmReapplyDecision = async () => {
    if (!api || !reapplyTarget) return;
    setActionLoading(true);
    try {
      const res = await api.crowdsec.reapplyDecision({
        id: reapplyTarget.id,
        type: reapplyTarget.type,
        duration: reapplyTarget.duration,
      });
      showActionSuccess('Decision reapplied', res.message || reapplyTarget.value);
      setReapplyTarget(null);
      await fetchAll();
    } catch (err) {
      showActionError('Failed to reapply decision', err);
    } finally {
      setActionLoading(false);
    }
  };

  const handleDecisionFilterChange = (filters: DecisionFilterState) => {
    setDecisionFilters(filters);
    setDecisionPage(1);
    void loadSecurityData({ nextDecisionFilters: filters, nextDecisionPage: 1 });
  };

  return (
    <PullToRefresh onRefresh={fetchAll}>
      <div className="pb-nav bg-canvas min-h-screen">
        <PageHeader
          eyebrow="Security"
          title="Watchtower."
          subtitle={`${decisionCount} decisions · ${alertCount} alerts`}
          action={
            <Pill tone="teal">
              <Dot tone="teal" pulse />
              live
            </Pill>
          }
        />

        <div className="px-md space-y-md">
          {/* Tab strip */}
          <div className="flex items-center gap-xxs overflow-x-auto bg-surface-soft rounded-pill p-xxs">
            {TABS.map((t) => (
              <CategoryTab key={t.id} active={activeTab === t.id} onClick={() => setActiveTab(t.id)}>
                {t.label}
              </CategoryTab>
            ))}
          </div>

          <QueryStateView
            isLoading={loading && !initialLoaded}
            error={error}
            onRetry={fetchAll}
            isEmpty={!decisions.length && !alertsAnalysis && !metrics}
            emptyTitle="No security data"
            emptyDescription="Refresh to load CrowdSec decisions, alerts, and metrics."
          >
            <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
              {/* ──── IP Tab ──── */}
              <TabsContent value="ip" className="space-y-md">
                <section className="rounded-lg bg-surface-card p-md space-y-sm">
                  <FieldLabel htmlFor="ip-check">IP address</FieldLabel>
                  <div className="flex gap-sm">
                    <Input
                      id="ip-check"
                      placeholder="203.0.113.42"
                      value={ipInput}
                      onChange={(e) => setIpInput(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && checkIP()}
                      className="font-mono"
                    />
                    <ButtonPrimary onClick={checkIP} disabled={actionLoading}>
                      <Search className="h-4 w-4" />
                      Check
                    </ButtonPrimary>
                  </div>
                </section>

                <IPBlockedResultCard result={ipBlockedResult} />
                <IPSecurityResultCard result={ipSecurityResult} />

                <section className="rounded-lg bg-primary p-md space-y-sm text-on-primary">
                  <div className="flex items-center justify-between gap-sm">
                    <div>
                      <p className="text-caption-uppercase uppercase font-medium opacity-80">Hero action</p>
                      <h3 className="font-display text-title-md">Unban an IP</h3>
                    </div>
                    <ShieldBan className="h-5 w-5 opacity-80" />
                  </div>
                  <div className="flex gap-sm">
                    <Input
                      placeholder="IP to unban"
                      value={unbanInput}
                      onChange={(e) => setUnbanInput(e.target.value)}
                      className="font-mono bg-canvas text-ink"
                    />
                    <ButtonSecondary
                      disabled={!unbanInput.trim() || actionLoading}
                      onClick={() => setUnbanTarget(unbanInput.trim())}
                    >
                      Unban
                    </ButtonSecondary>
                  </div>
                </section>
              </TabsContent>

              {/* ──── Decisions Tab ──── */}
              <TabsContent value="decisions" className="space-y-md">
                <AddDecisionForm onSubmit={addDecision} loading={actionLoading} />
                <DeleteDecisionForm onDelete={deleteDecisionByParams} loading={actionLoading} />

                <section className="rounded-lg bg-surface-card p-md space-y-sm">
                  <FieldLabel>Import decisions CSV</FieldLabel>
                  <Input type="file" accept=".csv" onChange={(e) => setImportFile(e.target.files?.[0] || null)} />
                  <ButtonPrimary onClick={importDecisions} disabled={!importFile || actionLoading}>
                    <Upload className="h-4 w-4" />Import
                  </ButtonPrimary>
                </section>

                <DecisionFilters onFiltersChange={handleDecisionFilterChange} />
                <DecisionsListPanel decisions={decisions} total={decisionsTotal} page={decisionPage} pageSize={PAGE_SIZE} />
                <PaginationControls
                  currentPage={decisionPage}
                  totalPages={decisionPageCount}
                  pageSize={PAGE_SIZE}
                  totalItems={decisionsTotal}
                  onPrev={() => {
                    const nextPage = Math.max(1, decisionPage - 1);
                    setDecisionPage(nextPage);
                    void loadSecurityData({ nextDecisionPage: nextPage });
                  }}
                  onNext={() => {
                    const nextPage = Math.min(decisionPageCount, decisionPage + 1);
                    setDecisionPage(nextPage);
                    void loadSecurityData({ nextDecisionPage: nextPage });
                  }}
                />
                <DecisionsAnalysisPanel data={decisionAnalysis} />
              </TabsContent>

              {/* ──── History Tab ──── */}
              <TabsContent value="history" className="space-y-md">
                <DecisionHistoryPanel
                  records={decisionHistory}
                  total={decisionHistoryTotal}
                  page={decisionHistoryPage}
                  onReapply={setReapplyTarget}
                />
                <PaginationControls
                  currentPage={decisionHistoryPage}
                  totalPages={decisionHistoryPageCount}
                  pageSize={PAGE_SIZE}
                  totalItems={decisionHistoryTotal}
                  onPrev={() => {
                    const nextPage = Math.max(1, decisionHistoryPage - 1);
                    setDecisionHistoryPage(nextPage);
                    void loadSecurityData({ nextHistoryPage: nextPage });
                  }}
                  onNext={() => {
                    const nextPage = Math.min(decisionHistoryPageCount, decisionHistoryPage + 1);
                    setDecisionHistoryPage(nextPage);
                    void loadSecurityData({ nextHistoryPage: nextPage });
                  }}
                />
              </TabsContent>

              {/* ──── Alerts Tab ──── */}
              <TabsContent value="alerts" className="space-y-md">
                {(() => {
                  const alertsList = alertsAnalysis?.alerts ?? alertsAnalysis?.recent ?? [];
                  return alertsList.length > 0 ? (
                    <AlertsListPanel
                      alerts={alertsList}
                      onDelete={(id) => setAlertDeleteId(id)}
                      onInspect={(id) => inspectAlert(id)}
                    />
                  ) : null;
                })()}

                <section className="rounded-lg bg-surface-card p-md space-y-sm">
                  <FieldLabel>Inspect alert by ID</FieldLabel>
                  <div className="flex gap-sm">
                    <Input placeholder="Alert ID" value={alertInspectId} onChange={(e) => setAlertInspectId(e.target.value)} />
                    <ButtonPrimary onClick={() => inspectAlert()} disabled={actionLoading || !alertInspectId.trim()}>
                      <FileSearch className="h-4 w-4" />Inspect
                    </ButtonPrimary>
                  </div>
                  {inspectedAlert?.id && (
                    <div className="flex justify-end">
                      <ButtonSecondary size="sm" onClick={() => setAlertDeleteId(inspectedAlert.id)}>
                        Delete alert #{inspectedAlert.id}
                      </ButtonSecondary>
                    </div>
                  )}
                </section>

                <AlertsAnalysisPanel data={alertsAnalysis} />
                <AlertDetailCard alert={inspectedAlert} />
              </TabsContent>

              {/* ──── Metrics Tab ──── */}
              <TabsContent value="metrics" className="space-y-md">
                <MetricsPanel metrics={metrics} />
              </TabsContent>
            </Tabs>
          </QueryStateView>
        </div>
      </div>

      <ConfirmActionDialog open={Boolean(unbanTarget)} onOpenChange={(open) => { if (!open) setUnbanTarget(null); }} title="Unban IP?" description={`This will remove active CrowdSec decision(s) for ${unbanTarget || 'this IP'}.`} confirmLabel="Unban" destructive loading={actionLoading} onConfirm={confirmUnban} />
      <ConfirmActionDialog open={alertDeleteId !== null} onOpenChange={(open) => { if (!open) setAlertDeleteId(null); }} title="Delete alert?" description={`Alert #${alertDeleteId || ''} will be removed from CrowdSec.`} confirmLabel="Delete" destructive loading={actionLoading} onConfirm={deleteAlert} />
      <ConfirmActionDialog
        open={Boolean(reapplyTarget)}
        onOpenChange={(open) => { if (!open) setReapplyTarget(null); }}
        title="Reapply decision?"
        description={reapplyTarget ? `This will reapply ${reapplyTarget.type} for ${reapplyTarget.value} with duration ${reapplyTarget.duration}.` : 'Reapply this historical decision.'}
        confirmLabel="Reapply"
        loading={actionLoading}
        onConfirm={confirmReapplyDecision}
      />
    </PullToRefresh>
  );
}

/* ────────────────────── IP Blocked Result Card ────────────────────── */

function IPBlockedResultCard({ result }: { result: IPBlockedStatus | null }) {
  if (!result) return null;
  return (
    <div className="rounded-lg border border-hairline bg-canvas p-md space-y-sm">
      <div className="flex items-center justify-between gap-sm">
        <div className="flex items-center gap-sm min-w-0">
          {result.blocked
            ? <ShieldX className="h-4 w-4 text-error shrink-0" />
            : <ShieldCheck className="h-4 w-4 text-success shrink-0" />}
          <span className="font-mono text-body-sm text-ink truncate">{result.ip}</span>
        </div>
        <Pill tone={result.blocked ? 'error' : 'success'}>
          {result.blocked ? 'Blocked' : 'Clear'}
        </Pill>
      </div>
      {result.reason && <p className="text-caption text-muted">Reason: {result.reason}</p>}
    </div>
  );
}

/* ────────────────────── IP Security Result Card ────────────────────── */

function IPSecurityResultCard({ result }: { result: IPSecurity | null }) {
  if (!result) return null;
  const fields: Array<{ label: string; value: boolean; icon: typeof Shield }> = [
    { label: 'Blocked', value: result.is_blocked, icon: ShieldX },
    { label: 'Whitelisted', value: result.is_whitelisted, icon: ShieldCheck },
    { label: 'In CrowdSec', value: result.in_crowdsec, icon: ShieldAlert },
    { label: 'In Traefik', value: result.in_traefik, icon: Shield },
  ];
  return (
    <div className="rounded-lg bg-surface-card p-md space-y-sm">
      <div className="flex items-center justify-between gap-sm">
        <h3 className="font-display text-title-sm text-ink">Security status</h3>
        <span className="font-mono text-caption text-muted truncate">{result.ip}</span>
      </div>
      <div className="grid grid-cols-2 gap-sm">
        {fields.map((field) => {
          const tone: PillTone = field.value
            ? (field.label === 'Blocked' ? 'error' : 'success')
            : 'outline';
          return (
            <div key={field.label} className="flex items-center justify-between gap-xs py-xxs">
              <span className="text-caption text-body">{field.label}</span>
              <Pill tone={tone}>{field.value ? 'Yes' : 'No'}</Pill>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ────────────────────── Decisions List Panel ────────────────────── */

function DecisionRow({ d }: { d: Decision }) {
  return (
    <div className="rounded-md bg-surface-dark-elevated p-sm space-y-xxs">
      <div className="flex items-center justify-between gap-sm">
        <span className="font-mono text-body-sm text-on-dark truncate">{d.value}</span>
        <Pill tone={decisionTone(d.type)}>{d.type}</Pill>
      </div>
      <div className="flex items-center gap-xs text-caption text-on-dark-soft flex-wrap">
        {d.scenario && <span className="truncate">{d.scenario}</span>}
        {d.duration && <><span>·</span><span className="shrink-0">{d.duration}</span></>}
      </div>
      <div className="flex items-center gap-xs text-caption text-on-dark-soft flex-wrap">
        <span>ID {d.id}</span>
        {d.alert_id && <><span>·</span><span>Alert #{d.alert_id}</span></>}
        {d.origin && <><span>·</span><span>{d.origin}</span></>}
        {d.scope && <><span>·</span><span>{d.scope}</span></>}
      </div>
    </div>
  );
}

function DecisionsListPanel({
  decisions, total, page, pageSize,
}: {
  decisions: Decision[]; total: number; page: number; pageSize: number;
}) {
  if (decisions.length === 0) {
    return (
      <div className="rounded-lg border border-hairline bg-canvas p-md">
        <h3 className="font-display text-title-sm text-ink mb-xs">Decisions</h3>
        <p className="text-caption text-muted">No active decisions.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg bg-surface-dark p-md space-y-sm text-on-dark">
      <div className="flex items-center justify-between gap-sm">
        <h3 className="font-display text-title-sm text-on-dark">Decisions feed</h3>
        <Pill tone="dark">{total}</Pill>
      </div>
      <p className="text-caption text-on-dark-soft">
        Page {page} · {decisions.length} of {total} active · {pageSize} per page
      </p>
      <div className="max-h-[50vh] overflow-y-auto space-y-sm">
        {decisions.map((d, i) => <DecisionRow key={d.id || i} d={d} />)}
      </div>
    </div>
  );
}

function PaginationControls({
  currentPage, totalPages, totalItems, pageSize, onPrev, onNext,
}: {
  currentPage: number; totalPages: number; totalItems: number; pageSize: number;
  onPrev: () => void; onNext: () => void;
}) {
  return (
    <div className="rounded-lg border border-hairline bg-canvas p-md flex items-center justify-between gap-sm">
      <div>
        <p className="text-body-sm font-medium text-ink">Pagination</p>
        <p className="text-caption text-muted">
          Page {currentPage} of {Math.max(totalPages, 1)} · {totalItems} items · {pageSize}/page
        </p>
      </div>
      <div className="flex gap-xs">
        <ButtonSecondary size="sm" onClick={onPrev} disabled={currentPage <= 1}>Prev</ButtonSecondary>
        <ButtonSecondary size="sm" onClick={onNext} disabled={currentPage >= totalPages}>Next</ButtonSecondary>
      </div>
    </div>
  );
}

function DecisionHistoryPanel({
  records, total, page, onReapply,
}: {
  records: DecisionHistoryRecord[]; total: number; page: number;
  onReapply: (record: DecisionHistoryRecord) => void;
}) {
  if (records.length === 0) {
    return (
      <div className="rounded-lg border border-hairline bg-canvas p-md">
        <h3 className="font-display text-title-sm text-ink mb-xs">Decision history</h3>
        <p className="text-caption text-muted">No history entries found.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg bg-surface-card p-md space-y-sm">
      <div className="flex items-center justify-between gap-sm">
        <div className="flex items-center gap-xs">
          <History className="h-4 w-4 text-muted" />
          <h3 className="font-display text-title-sm text-ink">Decision history</h3>
        </div>
        <Pill tone="cream">{total}</Pill>
      </div>
      <p className="text-caption text-muted">Page {page} · One-tap reapply.</p>
      <div className="max-h-[50vh] overflow-y-auto space-y-sm">
        {records.map((record) => (
          <div key={record.id} className="rounded-md border border-hairline bg-canvas p-sm space-y-xs">
            <div className="flex items-center justify-between gap-sm">
              <span className="font-mono text-body-sm text-ink truncate">{record.value}</span>
              <div className="flex items-center gap-xxs">
                <Pill tone={record.is_stale ? 'warning' : 'success'}>
                  {record.is_stale ? 'Stale' : 'Current'}
                </Pill>
                <Pill tone="outline">#{record.id}</Pill>
              </div>
            </div>
            <div className="flex items-center gap-xs text-caption text-muted flex-wrap">
              <span>{record.type}</span>
              {record.scope && <><span>·</span><span>{record.scope}</span></>}
              {record.scenario && <><span>·</span><span className="truncate">{record.scenario}</span></>}
              {record.duration && <><span>·</span><span>{record.duration}</span></>}
            </div>
            <div className="space-y-xxs">
              {record.created_at && <StatusRow label="Created" value={relativeTime(record.created_at)} />}
              {record.last_seen_at && <StatusRow label="Last seen" value={relativeTime(record.last_seen_at)} />}
              {record.until && <StatusRow label="Expires" value={relativeTime(record.until)} />}
            </div>
            <div className="flex justify-end">
              <ButtonSecondary size="sm" onClick={() => onReapply(record)}>
                <RotateCcw className="h-4 w-4" />Reapply
              </ButtonSecondary>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ────────────────────── Decisions Analysis Panel ────────────────────── */

function DecisionsAnalysisPanel({ data }: { data: DecisionsAnalysisData | null }) {
  if (!data) {
    return (
      <div className="rounded-lg border border-hairline bg-canvas p-md">
        <h3 className="font-display text-title-sm text-ink mb-xs">Decisions analysis</h3>
        <p className="text-caption text-muted">No analysis data.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg bg-surface-card p-md space-y-sm">
      <h3 className="font-display text-title-sm text-ink">Decisions analysis</h3>
      <div className="grid grid-cols-2 gap-sm">
        {data.total !== undefined && <MetricCard label="Total" value={data.total} />}
        {data.by_type && <MetricCard label="Types" value={Object.keys(data.by_type).length} />}
      </div>
      <BreakdownSection title="By type" data={data.by_type} />
      <BreakdownSection title="By origin" data={data.by_origin} />
      <BreakdownSection title="By scope" data={data.by_scope} />
      <ExtraFieldsRenderer data={data} exclude={['total', 'by_type', 'by_origin', 'by_scope', 'recent']} />
    </div>
  );
}

/* ────────────────────── Alerts Analysis Panel ────────────────────── */

function AlertsAnalysisPanel({ data }: { data: AlertsAnalysisData | null }) {
  if (!data) {
    return (
      <div className="rounded-lg border border-hairline bg-canvas p-md">
        <h3 className="font-display text-title-sm text-ink mb-xs">Alerts analysis</h3>
        <p className="text-caption text-muted">No analysis data.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg bg-surface-card p-md space-y-sm">
      <h3 className="font-display text-title-sm text-ink">Alerts analysis</h3>
      <div className="grid grid-cols-2 gap-sm">
        {data.count !== undefined && <MetricCard label="Total alerts" value={data.count} />}
        {data.by_scenario && <MetricCard label="Scenarios" value={Object.keys(data.by_scenario).length} />}
      </div>
      <BreakdownSection title="By scenario" data={data.by_scenario} />
      <BreakdownSection title="By scope" data={data.by_scope} />

      {data.recent && data.recent.length > 0 && (
        <div className="space-y-xs">
          <h4 className="text-caption-uppercase uppercase font-medium text-muted">Recent alerts</h4>
          <div className="max-h-[30vh] overflow-y-auto space-y-xs">
            {data.recent.slice(0, 10).map((alert, i) => (
              <div key={alert.id || i} className="rounded-md border border-hairline bg-canvas p-sm space-y-xxs">
                <div className="flex items-center justify-between gap-sm">
                  <span className="text-body-sm text-ink truncate">{alert.scenario || 'Alert'}</span>
                  {alert.id && <Pill tone="outline">#{alert.id}</Pill>}
                </div>
                <div className="flex items-center gap-xs text-caption text-muted">
                  {alert.scope && <span>{alert.scope}</span>}
                  {alert.value && <><span>·</span><span className="font-mono truncate">{alert.value}</span></>}
                </div>
                {alert.start_at && <p className="text-caption text-muted-soft">{relativeTime(alert.start_at)}</p>}
              </div>
            ))}
          </div>
        </div>
      )}

      <ExtraFieldsRenderer data={data} exclude={['count', 'by_scenario', 'by_scope', 'recent']} />
    </div>
  );
}

/* ────────────────────── Alert Detail Card ────────────────────── */

function AlertDetailCard({ alert }: { alert: CrowdsecAlert | null }) {
  if (!alert) return null;
  return (
    <div className="rounded-lg bg-surface-card p-md space-y-sm">
      <div className="flex items-center justify-between gap-sm">
        <h3 className="font-display text-title-sm text-ink truncate">{alert.scenario || 'Alert'}</h3>
        <Pill tone="outline">#{alert.id}</Pill>
      </div>
      <div className="space-y-xxs">
        {alert.scope && <StatusRow label="Scope" value={alert.scope} />}
        {alert.value && <StatusRow label="Value" value={alert.value} mono />}
        {alert.origin && <StatusRow label="Origin" value={alert.origin} />}
        {alert.type && <StatusRow label="Type" value={alert.type} />}
        {alert.events_count !== undefined && <StatusRow label="Events" value={String(alert.events_count)} />}
      </div>
      {alert.source && (
        <>
          <Separator />
          <h4 className="text-caption-uppercase uppercase font-medium text-muted">Source</h4>
          <div className="space-y-xxs">
            {alert.source.ip && <StatusRow label="IP" value={alert.source.ip} mono />}
            {alert.source.cn && <StatusRow label="Country" value={alert.source.cn} />}
            {alert.source.as_name && <StatusRow label="AS Name" value={alert.source.as_name} />}
          </div>
        </>
      )}
      {(alert.start_at || alert.stop_at) && (
        <>
          <Separator />
          <div className="space-y-xxs">
            {alert.start_at && <StatusRow label="Start" value={new Date(alert.start_at).toLocaleString()} />}
            {alert.stop_at && <StatusRow label="Stop" value={new Date(alert.stop_at).toLocaleString()} />}
          </div>
        </>
      )}
      {alert.message && (<><Separator /><p className="text-caption text-muted">{alert.message}</p></>)}
    </div>
  );
}

/* ────────────────────── Metrics Panel ────────────────────── */

function MetricsPanel({ metrics }: { metrics: MetricsResponse | null }) {
  if (!metrics) {
    return (
      <div className="rounded-lg border border-hairline bg-canvas p-md">
        <h3 className="font-display text-title-sm text-ink mb-xs">CrowdSec metrics</h3>
        <p className="text-caption text-muted">No metrics available.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg bg-surface-card p-md space-y-sm">
      <h3 className="font-display text-title-sm text-ink">CrowdSec metrics</h3>
      <div className="space-y-xs">
        {Object.entries(metrics).map(([sectionName, sectionData]) => (
          <details key={sectionName}>
            <summary className="text-body-sm font-medium text-ink cursor-pointer hover:text-primary py-xs border-b border-hairline-soft">
              {fmtKey(sectionName)}
            </summary>
            <div className="mt-xs space-y-xxs">
              {typeof sectionData === 'object' && sectionData !== null ? (
                <RecursiveStatusRows data={sectionData as Record<string, unknown>} depth={0} />
              ) : (
                <StatusRow label={sectionName} value={String(sectionData ?? '—')} mono />
              )}
            </div>
          </details>
        ))}
      </div>
    </div>
  );
}

/* ────────────────────── Shared Components ────────────────────── */

function BreakdownSection({ title, data }: { title: string; data?: Record<string, number> }) {
  if (!data || Object.keys(data).length === 0) return null;

  return (
    <div className="space-y-xxs">
      <h4 className="text-caption-uppercase uppercase font-medium text-muted">{title}</h4>
      {Object.entries(data)
        .sort(([, a], [, b]) => b - a)
        .map(([key, value]) => (
          <div key={key} className="flex items-center justify-between py-xxs">
            <span className="text-caption text-body truncate">{fmtKey(key)}</span>
            <span className="text-caption font-mono text-ink shrink-0">{value.toLocaleString()}</span>
          </div>
        ))}
    </div>
  );
}

function RecursiveStatusRows({ data, depth }: { data: Record<string, unknown>; depth: number }) {
  return (
    <>
      {Object.entries(data).map(([key, value]) => {
        if (value === null || value === undefined) return null;

        if (typeof value === 'object') {
          if (Array.isArray(value)) {
            return (
              <div key={key} className={depth > 0 ? 'ml-sm' : ''}>
                <StatusRow label={fmtKey(key)} value={`${value.length} items`} />
              </div>
            );
          }
          if (depth < 2) {
            return (
              <details key={key} className={depth > 0 ? 'ml-sm' : ''}>
                <summary className="text-caption text-muted cursor-pointer hover:text-ink py-xxs">
                  {fmtKey(key)}
                </summary>
                <div className="mt-xxs space-y-xxs">
                  <RecursiveStatusRows data={value as Record<string, unknown>} depth={depth + 1} />
                </div>
              </details>
            );
          }
          return (
            <div key={key} className={depth > 0 ? 'ml-sm' : ''}>
              <StatusRow label={fmtKey(key)} value={`${Object.keys(value as object).length} fields`} />
            </div>
          );
        }

        return (
          <div key={key} className={depth > 0 ? 'ml-sm' : ''}>
            <StatusRow label={fmtKey(key)} value={String(value)} mono />
          </div>
        );
      })}
    </>
  );
}

function ExtraFieldsRenderer({ data, exclude }: { data: Record<string, unknown>; exclude: string[] }) {
  const extras = Object.entries(data).filter(
    ([key, value]) => !exclude.includes(key) && value !== null && value !== undefined && typeof value !== 'object',
  );

  if (extras.length === 0) return null;

  return (
    <div className="space-y-xxs">
      {extras.map(([key, value]) => (
        <StatusRow key={key} label={fmtKey(key)} value={typeof value === 'number' ? value.toLocaleString() : String(value)} />
      ))}
    </div>
  );
}

/* ────────────────────── Helpers ────────────────────── */

function fmtKey(key: string): string {
  return key.replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/\b\w/g, (c) => c.toUpperCase());
}
