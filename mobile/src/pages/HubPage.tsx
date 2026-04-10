import { useCallback, useMemo, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { ArrowUpCircle, Check, Download, RefreshCw, Trash2, Wrench, History, Save, X } from 'lucide-react';
import { relativeTime } from '@/lib/utils';
import { useApi } from '@/contexts/ApiContext';
import { PageHeader } from '@/components/PageHeader';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { QueryStateView } from '@/components/QueryStateView';
import { FormDialog } from '@/components/FormDialog';
import { StatusDot } from '@/components/StatusDot';
import { StatusRow } from '@/components/StatusRow';
import { MetricCard } from '@/components/MetricCard';
import { showActionError, showActionSuccess } from '@/lib/actionToast';
import { parseHubItems } from '@/lib/api/hub';
import type { HubCategory, HubCategoryItem, HubCategoryItemsResponse, HubOperationRecord, HubPreference } from '@/lib/api';

export default function HubPage() {
  const { api } = useApi();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  const [hubSummary, setHubSummary] = useState<unknown>(null);
  const [categories, setCategories] = useState<HubCategory[]>([]);
  const [activeCategory, setActiveCategory] = useState('all');
  const [itemsPayload, setItemsPayload] = useState<HubCategoryItemsResponse | null>(null);

  const [itemName, setItemName] = useState('');
  const [showManualDialog, setShowManualDialog] = useState(false);
  const [manualFilename, setManualFilename] = useState('custom.yaml');
  const [manualYaml, setManualYaml] = useState('');
  const [manualTargetPath, setManualTargetPath] = useState('');

  const [preferences, setPreferences] = useState<HubPreference[]>([]);
  const [activePreference, setActivePreference] = useState<HubPreference | null>(null);

  const [historyRows, setHistoryRows] = useState<HubOperationRecord[]>([]);
  const [historyInspectId, setHistoryInspectId] = useState('');
  const [historyInspect, setHistoryInspect] = useState<HubOperationRecord | null>(null);

  const loadCategoryItems = useCallback(async (categoryOverride?: string) => {
    const category = categoryOverride || activeCategory;
    if (!api || !category) return;
    if (category === 'all') {
      setItemsPayload(null);
      setActivePreference(null);
      return;
    }

    try {
      const payload = await api.hub.items(category);
      setItemsPayload(payload);

      const pref = await api.hub.preference(category);
      setActivePreference(pref || null);
    } catch (err) {
      showActionError('Failed to load category data', err);
      setItemsPayload(null);
      setActivePreference(null);
    }
  }, [activeCategory, api]);

  const load = useCallback(async () => {
    if (!api) return;

    setLoading(true);
    setError(null);

    try {
      const [summaryRes, categoriesRes, prefRes, historyRes] = await Promise.all([
        api.hub.list(),
        api.hub.categories(),
        api.hub.preferences(),
        api.hub.history({ limit: 20 }),
      ]);

      setHubSummary(summaryRes);
      setCategories(categoriesRes || []);
      setPreferences(prefRes || []);
      setHistoryRows(historyRes || []);

      setActiveCategory((prev) => {
        const selected = prev || 'all';
        if (selected && selected !== 'all') {
          loadCategoryItems(selected);
        }
        return selected;
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load hub data');
    } finally {
      setLoading(false);
    }
  }, [api, loadCategoryItems]);

  useMountEffect(() => {
    load();
  });

  const parsedItems = useMemo(() => {
    if (activeCategory === 'all') return parseHubItems(hubSummary);
    return parseHubItems(itemsPayload?.items ?? itemsPayload?.raw_output ?? null);
  }, [activeCategory, hubSummary, itemsPayload]);

  const isAllCategory = activeCategory === 'all';
  const groupedCategoryItems = parsedItems.groupedItems;
  const categoryItems = isAllCategory
    ? parsedItems.items
    : parsedItems.items.length > 0
      ? parsedItems.items
      : Object.values(groupedCategoryItems).flat();
  const itemsEmpty = isAllCategory
    ? Object.keys(groupedCategoryItems).length === 0
    : categoryItems.length === 0;

  const runCategoryAction = async (type: 'install' | 'remove') => {
    if (!api || !activeCategory || activeCategory === 'all' || !itemName.trim()) return;

    setActionLoading(true);
    try {
      const response =
        type === 'install'
          ? await api.hub.install(activeCategory, itemName.trim())
          : await api.hub.remove(activeCategory, itemName.trim());

      showActionSuccess(type === 'install' ? 'Hub item installed' : 'Hub item removed', response.message || itemName.trim());
      setItemName('');
      await Promise.all([loadCategoryItems(activeCategory), load()]);
    } catch (err) {
      showActionError(type === 'install' ? 'Install failed' : 'Remove failed', err);
    } finally {
      setActionLoading(false);
    }
  };

  const upgradeAll = async () => {
    if (!api) return;

    setActionLoading(true);
    try {
      const response = await api.hub.upgradeAll();
      showActionSuccess('Hub upgraded', response.message || 'All hub items upgraded');
      await load();
      await loadCategoryItems(activeCategory);
    } catch (err) {
      showActionError('Hub upgrade failed', err);
    } finally {
      setActionLoading(false);
    }
  };

  const applyManualYaml = async () => {
    if (!api || !activeCategory || activeCategory === 'all' || !manualFilename.trim() || !manualYaml.trim()) return;

    setActionLoading(true);
    try {
      const response = await api.hub.manualApply(activeCategory, {
        filename: manualFilename.trim(),
        yaml: manualYaml,
        target_path: manualTargetPath.trim() || undefined,
      });
      showActionSuccess('Manual YAML applied', response.message || response.data?.path || activeCategory);
      setShowManualDialog(false);
      await Promise.all([load(), loadCategoryItems(activeCategory)]);
    } catch (err) {
      showActionError('Manual apply failed', err);
    } finally {
      setActionLoading(false);
    }
  };

  const savePreference = async () => {
    if (!api || !activeCategory || activeCategory === 'all' || !activePreference) return;

    setActionLoading(true);
    try {
      const response = await api.hub.updatePreference(activeCategory, {
        default_mode: activePreference.default_mode,
        default_yaml_path: activePreference.default_yaml_path,
        last_item_name: activePreference.last_item_name,
      });
      showActionSuccess('Preference saved', response.message || activeCategory);
      await load();
      await loadCategoryItems(activeCategory);
    } catch (err) {
      showActionError('Failed to save preference', err);
    } finally {
      setActionLoading(false);
    }
  };

  const inspectHistory = async () => {
    if (!api || !historyInspectId.trim()) return;

    setActionLoading(true);
    try {
      const record = await api.hub.historyById(Number(historyInspectId.trim()));
      setHistoryInspect(record);
      showActionSuccess('History record loaded', `#${historyInspectId.trim()}`);
    } catch (err) {
      showActionError('Failed to inspect history', err);
      setHistoryInspect(null);
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="pb-nav">
      <PageHeader
        title="Hub"
        subtitle="Browse, install, remove, apply, preference, history"
        action={
          <div className="flex gap-1">
            <Button variant="ghost" size="icon" onClick={load} disabled={loading}>
              <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
            </Button>
            <Button variant="secondary" size="sm" onClick={upgradeAll} disabled={actionLoading}>
              <ArrowUpCircle className="h-4 w-4 mr-1" />
              Upgrade all
            </Button>
          </div>
        }
      />

      <div className="px-4 space-y-4">
        <Tabs defaultValue="items" className="w-full">
          <TabsList className="w-full grid grid-cols-4">
            <TabsTrigger value="items">Items</TabsTrigger>
            <TabsTrigger value="manual">Manual</TabsTrigger>
            <TabsTrigger value="prefs">Prefs</TabsTrigger>
            <TabsTrigger value="history">History</TabsTrigger>
          </TabsList>

          {/* ──── Items Tab ──── */}
          <TabsContent value="items" className="space-y-3">
            {/* Hub Summary */}
            <HubSummaryPanel summary={hubSummary} categories={categories} />

            {/* Category Selector */}
            <section className="rounded-xl border border-border bg-card p-4 space-y-3">
              <h3 className="text-sm font-semibold">Category</h3>
              <div className="flex gap-2 overflow-x-auto pb-1">
                <Button
                  key="all"
                  variant={isAllCategory ? 'default' : 'secondary'}
                  size="sm"
                  onClick={() => {
                    setActiveCategory('all');
                    setItemsPayload(null);
                    setActivePreference(null);
                  }}
                  className="whitespace-nowrap"
                >
                  all
                </Button>
                {categories.map((category) => (
                  <Button
                    key={category.key}
                    variant={activeCategory === category.key ? 'default' : 'secondary'}
                    size="sm"
                    onClick={() => {
                      setActiveCategory(category.key);
                      loadCategoryItems(category.key);
                    }}
                    className="whitespace-nowrap"
                  >
                    {category.key}
                  </Button>
                ))}
              </div>
              <div className="flex gap-2">
                <Input
                  placeholder={isAllCategory ? 'Select a category first' : 'item name'}
                  value={itemName}
                  onChange={(e) => setItemName(e.target.value)}
                  disabled={isAllCategory}
                />
                <Button onClick={() => runCategoryAction('install')} disabled={isAllCategory || !itemName.trim() || actionLoading}>
                  <Download className="h-4 w-4 mr-1" />Install
                </Button>
                <Button variant="destructive" onClick={() => runCategoryAction('remove')} disabled={isAllCategory || !itemName.trim() || actionLoading}>
                  <Trash2 className="h-4 w-4 mr-1" />Remove
                </Button>
              </div>
            </section>

            {/* Category Items */}
            <section className="rounded-xl border border-border bg-card p-4">
              <h3 className="text-sm font-semibold mb-2">{isAllCategory ? 'All category overview' : 'Category items'}</h3>
              <QueryStateView isLoading={loading} error={error} onRetry={() => (isAllCategory ? load() : loadCategoryItems(activeCategory))} isEmpty={itemsEmpty} emptyTitle="No items parsed" emptyDescription="Try another category or refresh the hub overview.">
                {isAllCategory ? <GroupedHubItemsList groupedItems={groupedCategoryItems} /> : <HubItemsList items={categoryItems} />}
              </QueryStateView>
              {!isAllCategory && itemsPayload?.raw_output && (
                <details className="mt-3">
                  <summary className="text-xs text-muted-foreground cursor-pointer">Raw output</summary>
                  <pre className="mt-2 text-xs font-mono whitespace-pre-wrap overflow-x-auto max-h-[30vh] overflow-y-auto">
                    {String(itemsPayload.raw_output)}
                  </pre>
                </details>
              )}
            </section>
          </TabsContent>

          {/* ──── Manual Tab ──── */}
          <TabsContent value="manual" className="space-y-3">
            <section className="rounded-xl border border-border bg-card p-4 space-y-3">
              <h3 className="text-sm font-semibold">Manual apply YAML</h3>
              <p className="text-xs text-muted-foreground">Applies via `/api/hub/:category/manual-apply`.</p>
              <Button onClick={() => setShowManualDialog(true)} disabled={isAllCategory}>
                <Wrench className="h-4 w-4 mr-1" />Open manual apply
              </Button>
              {isAllCategory && <p className="text-xs text-muted-foreground">Choose a specific category before applying YAML.</p>}
            </section>
          </TabsContent>

          {/* ──── Prefs Tab ──── */}
          <TabsContent value="prefs" className="space-y-3">
            <PreferencesPanel preferences={preferences} />

            <section className="rounded-xl border border-border bg-card p-4 space-y-2">
              <h3 className="text-sm font-semibold">Edit active category preference</h3>
              {activePreference ? (
                <>
                  <div className="flex gap-2">
                    <Button size="sm" variant={activePreference.default_mode === 'direct' ? 'default' : 'secondary'} onClick={() => setActivePreference((prev) => (prev ? { ...prev, default_mode: 'direct' } : prev))}>
                      Direct
                    </Button>
                    <Button size="sm" variant={activePreference.default_mode === 'manual' ? 'default' : 'secondary'} onClick={() => setActivePreference((prev) => (prev ? { ...prev, default_mode: 'manual' } : prev))}>
                      Manual
                    </Button>
                  </div>
                  <Input placeholder="Default YAML path" value={activePreference.default_yaml_path || ''} onChange={(e) => setActivePreference((prev) => (prev ? { ...prev, default_yaml_path: e.target.value } : prev))} />
                  <Input placeholder="Last item name" value={activePreference.last_item_name || ''} onChange={(e) => setActivePreference((prev) => (prev ? { ...prev, last_item_name: e.target.value } : prev))} />
                  <Button onClick={savePreference} disabled={actionLoading}>
                    <Save className="h-4 w-4 mr-1" />Save preference
                  </Button>
                </>
              ) : (
                <p className="text-sm text-muted-foreground">Select a specific category to load preference data.</p>
              )}
            </section>
          </TabsContent>

          {/* ──── History Tab ──── */}
          <TabsContent value="history" className="space-y-3">
            <section className="rounded-xl border border-border bg-card p-4 space-y-2">
              <h3 className="text-sm font-semibold">Inspect history record</h3>
              <div className="flex gap-2">
                <Input placeholder="History ID" value={historyInspectId} onChange={(e) => setHistoryInspectId(e.target.value)} />
                <Button onClick={inspectHistory} disabled={!historyInspectId.trim() || actionLoading}>
                  <History className="h-4 w-4 mr-1" />Inspect
                </Button>
              </div>
            </section>

            <HistoryListPanel records={historyRows} />

            {historyInspect && <HistoryDetailCard record={historyInspect} />}
          </TabsContent>
        </Tabs>
      </div>

      <FormDialog
        open={showManualDialog}
        onOpenChange={setShowManualDialog}
        title={`Manual apply (${activeCategory || 'category'})`}
        description="POST /api/hub/:category/manual-apply"
        submitLabel="Apply"
        loading={actionLoading}
        onSubmit={applyManualYaml}
      >
        <Input placeholder="Filename (e.g. custom.yaml)" value={manualFilename} onChange={(e) => setManualFilename(e.target.value)} />
        <Input placeholder="Target path (optional)" value={manualTargetPath} onChange={(e) => setManualTargetPath(e.target.value)} />
        <Textarea placeholder="YAML content" value={manualYaml} onChange={(e) => setManualYaml(e.target.value)} className="min-h-[200px]" />
      </FormDialog>
    </div>
  );
}

/* ────────────────────── Hub Summary Panel ────────────────────── */

function HubSummaryPanel({ summary, categories }: { summary: unknown; categories: HubCategory[] }) {
  // Build category item counts from the hub list response
  // Backend returns: {"collections": {name: {...}, ...}, "scenarios": {...}, ...}
  const categoryCountEntries: Array<[string, number]> = [];
  if (summary && typeof summary === 'object') {
    const record = summary as Record<string, unknown>;
    for (const [key, v] of Object.entries(record)) {
      if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
        const count = Object.keys(v as object).length;
        if (count > 0) categoryCountEntries.push([key, count]);
      } else if (typeof v === 'number') {
        categoryCountEntries.push([key, v]);
      }
    }
  }

  const hasData = categoryCountEntries.length > 0;

  return (
    <div className="rounded-xl border border-border bg-card p-4 space-y-3">
      <h3 className="text-sm font-semibold">Hub Summary</h3>
      <div className="grid grid-cols-2 gap-2">
        {hasData ? (
          categoryCountEntries.slice(0, 4).map(([key, count]) => (
            <MetricCard key={key} label={fmtKey(key)} value={count} />
          ))
        ) : (
          <MetricCard label="Categories" value={categories.length} />
        )}
      </div>
    </div>
  );
}

/* ────────────────────── Hub Items List ────────────────────── */

function HubItemsList({ items }: { items: HubCategoryItem[] }) {
  return (
    <div className="max-h-[40vh] overflow-y-auto">
      <div className="space-y-2">
        {items.map((item, i) => {
          const obj = typeof item === 'object' && item !== null ? (item as Record<string, unknown>) : null;
          if (!obj) return <div key={i} className="text-xs text-muted-foreground">{String(item)}</div>;

          const name = String(obj.name || obj.Name || obj.title || `Item ${i + 1}`);
          const version = obj.version || obj.local_version;
          const status = obj.status || (obj.installed ? 'installed' : 'available');

          return (
            <div key={name + i} className="rounded-lg border border-border/50 bg-muted/30 p-3 space-y-1">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium truncate">{name}</span>
                {status && (
                  <Badge variant={String(status) === 'installed' || String(status) === 'enabled' ? 'success' : 'outline'} className="text-[10px] shrink-0">
                    {String(status)}
                  </Badge>
                )}
              </div>
              {version && <span className="text-[10px] text-muted-foreground font-mono">v{String(version)}</span>}
              {obj.description && <p className="text-[10px] text-muted-foreground truncate">{String(obj.description)}</p>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function GroupedHubItemsList({ groupedItems }: { groupedItems: Record<string, HubCategoryItem[]> }) {
  return (
    <div className="space-y-3">
      {Object.entries(groupedItems)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([category, items]) => (
          <section key={category} className="rounded-lg border border-border/50 bg-muted/20 p-3 space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{fmtKey(category)}</h4>
              <Badge variant="outline" className="text-[10px]">{items.length}</Badge>
            </div>
            <HubItemsList items={items} />
          </section>
        ))}
    </div>
  );
}

/* ────────────────────── Preferences Panel ────────────────────── */

function PreferencesPanel({ preferences }: { preferences: HubPreference[] }) {
  if (preferences.length === 0) {
    return (
      <div className="rounded-xl border border-border bg-card p-4">
        <h3 className="text-sm font-semibold mb-2">All preferences</h3>
        <p className="text-xs text-muted-foreground">No preferences configured.</p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-border bg-card p-4 space-y-2">
      <h3 className="text-sm font-semibold">All preferences</h3>
      <div className="space-y-2">
        {preferences.map((pref) => (
          <div key={pref.category} className="rounded-lg border border-border/50 bg-muted/30 p-3 space-y-1">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-medium">{pref.category}</span>
              <Badge variant={pref.default_mode === 'direct' ? 'default' : 'secondary'} className="text-[10px]">
                {pref.default_mode}
              </Badge>
            </div>
            {pref.last_item_name && (
              <p className="text-[10px] text-muted-foreground">Last: {pref.last_item_name}</p>
            )}
            {pref.updated_at && (
              <p className="text-[10px] text-muted-foreground">{new Date(pref.updated_at).toLocaleDateString()}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ────────────────────── History List Panel ────────────────────── */

function HistoryListPanel({ records }: { records: HubOperationRecord[] }) {
  if (records.length === 0) {
    return (
      <div className="rounded-xl border border-border bg-card p-4">
        <h3 className="text-sm font-semibold mb-2">History</h3>
        <p className="text-xs text-muted-foreground">No operation history.</p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-border bg-card p-4 space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">History</h3>
        <Badge variant="outline">{records.length}</Badge>
      </div>
      <div className="max-h-[40vh] overflow-y-auto">
        <div className="space-y-2">
          {records.map((record) => (
            <div key={record.id} className="rounded-lg border border-border/50 bg-muted/30 p-3 space-y-1">
              <div className="flex items-center gap-2">
                <StatusDot color={record.success ? 'success' : 'error'} />
                <span className="text-xs font-medium">{record.action}</span>
                <span className="text-[10px] text-muted-foreground">·</span>
                <span className="text-[10px] text-muted-foreground">{record.category}</span>
                <Badge variant="outline" className="text-[10px] ml-auto">#{record.id}</Badge>
              </div>
              {record.item_name && <p className="text-xs truncate">{record.item_name}</p>}
              {record.created_at && (
                <p className="text-[10px] text-muted-foreground">{relativeTime(record.created_at)}</p>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ────────────────────── History Detail Card ────────────────────── */

function HistoryDetailCard({ record }: { record: HubOperationRecord }) {
  return (
    <div className="rounded-xl border border-border bg-card p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">History #{record.id}</h3>
        <Badge variant={record.success ? 'success' : 'destructive'}>{record.success ? 'Success' : 'Failed'}</Badge>
      </div>
      <div className="space-y-0.5">
        <StatusRow label="Action" value={record.action} />
        <StatusRow label="Category" value={record.category} />
        <StatusRow label="Mode" value={record.mode} />
        {record.item_name && <StatusRow label="Item" value={record.item_name} />}
        {record.yaml_path && <StatusRow label="YAML Path" value={record.yaml_path} mono />}
        {record.created_at && <StatusRow label="Timestamp" value={relativeTime(record.created_at)} />}
      </div>
      {record.command && (
        <>
          <h4 className="text-xs font-medium text-muted-foreground">Command</h4>
          <pre className="text-[10px] font-mono whitespace-pre-wrap bg-muted/50 rounded-lg p-2">{record.command}</pre>
        </>
      )}
      {record.output && (
        <details>
          <summary className="text-xs text-muted-foreground cursor-pointer">Output</summary>
          <pre className="mt-1 text-[10px] font-mono whitespace-pre-wrap overflow-x-auto max-h-[20vh] overflow-y-auto bg-muted/50 rounded-lg p-2">
            {record.output}
          </pre>
        </details>
      )}
      {record.error && (
        <div className="rounded-lg bg-red-500/10 border border-red-500/20 p-3">
          <h4 className="text-xs font-medium text-red-600 dark:text-red-400 mb-1">Error</h4>
          <pre className="text-[10px] font-mono whitespace-pre-wrap text-red-600 dark:text-red-400">{record.error}</pre>
        </div>
      )}
    </div>
  );
}

/* ────────────────────── Helpers ────────────────────── */

function fmtKey(key: string): string {
  return key.replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/\b\w/g, (c) => c.toUpperCase());
}
