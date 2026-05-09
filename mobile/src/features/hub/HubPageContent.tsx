import { useCallback, useMemo, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { Download, History, Save, Trash2, Wrench } from 'lucide-react';
import { relativeTime, cn } from '@/lib/utils';
import { useApi } from '@/contexts/ApiContext';
import { TopBar } from '@/components/TopBar';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { QueryStateView } from '@/components/QueryStateView';
import { FormDialog } from '@/components/FormDialog';
import { ButtonPrimary, ButtonSecondary, Dot, Pill, UpperBadge } from '@/components/design';
import { showActionError, showActionSuccess } from '@/lib/actionToast';
import { parseHubItems } from '@/lib/api/hub';
import type {
  HubCategory,
  HubCategoryItem,
  HubCategoryItemsResponse,
  HubOperationRecord,
  HubPreference,
} from '@/lib/api';

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

  const loadCategoryItems = useCallback(
    async (categoryOverride?: string) => {
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
    },
    [activeCategory, api],
  );

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
        if (selected && selected !== 'all') loadCategoryItems(selected);
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

  const summaryCounts = useMemo(() => {
    const out: Array<[string, number]> = [];
    if (hubSummary && typeof hubSummary === 'object') {
      for (const [key, v] of Object.entries(hubSummary as Record<string, unknown>)) {
        if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
          out.push([key, Object.keys(v as object).length]);
        } else if (typeof v === 'number') {
          out.push([key, v]);
        }
      }
    }
    return out;
  }, [hubSummary]);

  const featuredItem = useMemo(() => {
    if (!parsedItems.items.length) return null;
    const item = parsedItems.items[0];
    if (typeof item !== 'object' || item === null) return null;
    return item as Record<string, unknown>;
  }, [parsedItems]);

  const runCategoryAction = async (type: 'install' | 'remove') => {
    if (!api || !activeCategory || activeCategory === 'all' || !itemName.trim()) return;
    setActionLoading(true);
    try {
      const response =
        type === 'install'
          ? await api.hub.install(activeCategory, itemName.trim())
          : await api.hub.remove(activeCategory, itemName.trim());
      showActionSuccess(
        type === 'install' ? 'Hub item installed' : 'Hub item removed',
        response.message || itemName.trim(),
      );
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

  const featuredName = featuredItem ? String(featuredItem.name || featuredItem.Name || 'Latest item') : null;
  const featuredVersion = featuredItem
    ? String(featuredItem.version || featuredItem.local_version || '0.0.0')
    : '0.0.0';
  const featuredDescription = featuredItem ? String(featuredItem.description || '') : '';

  return (
    <div className="pb-nav bg-canvas">
      <TopBar title="Hub" right={<Pill tone="success">Up to date</Pill>} />

      <div className="px-md py-md space-y-md">
        {/* Coral release callout — featured item */}
        {featuredName ? (
          <div className="rounded-lg bg-primary text-on-primary p-lg">
            <UpperBadge tone="cream">New</UpperBadge>
            <h2 className="mt-sm font-display text-display-sm truncate">
              {featuredName} {featuredVersion}
            </h2>
            {featuredDescription && (
              <p className="mt-xxs text-body-sm opacity-90 line-clamp-2">{featuredDescription}</p>
            )}
            <div className="mt-md">
              <ButtonSecondary onClick={upgradeAll} disabled={actionLoading}>
                Upgrade all
              </ButtonSecondary>
            </div>
          </div>
        ) : (
          <div className="rounded-lg bg-surface-card p-lg">
            <UpperBadge tone="cream">Up to date</UpperBadge>
            <h2 className="mt-sm font-display text-display-sm text-ink">No new releases.</h2>
            <p className="mt-xxs text-body-sm text-muted">Refresh to check for hub updates.</p>
          </div>
        )}

        {/* 2×2 count grid */}
        <div className="grid grid-cols-2 gap-sm">
          {summaryCounts.length > 0 ? (
            summaryCounts.slice(0, 4).map(([key, count]) => (
              <div key={key} className="rounded-lg bg-surface-card p-md">
                <div className="text-caption-uppercase uppercase text-muted">{fmtKey(key)}</div>
                <div className="mt-xxs font-display text-display-sm text-ink">{count}</div>
              </div>
            ))
          ) : (
            <div className="rounded-lg bg-surface-card p-md col-span-2">
              <div className="text-caption-uppercase uppercase text-muted">Categories</div>
              <div className="mt-xxs font-display text-display-sm text-ink">{categories.length}</div>
            </div>
          )}
        </div>

        <Tabs defaultValue="items" className="w-full">
          <TabsList className="w-full grid grid-cols-4">
            <TabsTrigger value="items">Items</TabsTrigger>
            <TabsTrigger value="manual">Manual</TabsTrigger>
            <TabsTrigger value="prefs">Prefs</TabsTrigger>
            <TabsTrigger value="history">History</TabsTrigger>
          </TabsList>

          <TabsContent value="items" className="space-y-sm pt-sm">
            <section className="rounded-lg bg-surface-card p-md space-y-sm">
              <div className="font-display text-title-md text-ink">Category</div>
              <div className="flex gap-xs overflow-x-auto pb-xxs">
                <CategoryPill
                  active={isAllCategory}
                  onClick={() => {
                    setActiveCategory('all');
                    setItemsPayload(null);
                    setActivePreference(null);
                  }}
                >
                  all
                </CategoryPill>
                {categories.map((category) => (
                  <CategoryPill
                    key={category.key}
                    active={activeCategory === category.key}
                    onClick={() => {
                      setActiveCategory(category.key);
                      loadCategoryItems(category.key);
                    }}
                  >
                    {category.key}
                  </CategoryPill>
                ))}
              </div>
              <div className="flex gap-xs">
                <Input
                  placeholder={isAllCategory ? 'Select a category first' : 'item name'}
                  value={itemName}
                  onChange={(e) => setItemName(e.target.value)}
                  disabled={isAllCategory}
                />
                <ButtonPrimary
                  size="sm"
                  onClick={() => runCategoryAction('install')}
                  disabled={isAllCategory || !itemName.trim() || actionLoading}
                >
                  <Download className="h-4 w-4 mr-1" />
                  Install
                </ButtonPrimary>
                <button
                  onClick={() => runCategoryAction('remove')}
                  disabled={isAllCategory || !itemName.trim() || actionLoading}
                  className="h-9 px-md rounded-md text-button font-medium inline-flex items-center justify-center gap-xs bg-error/10 text-error hover:bg-error/20 disabled:opacity-50 transition-colors"
                >
                  <Trash2 className="h-4 w-4" />
                  Remove
                </button>
              </div>
            </section>

            <section className="rounded-lg bg-surface-card p-md">
              <h3 className="font-display text-title-md text-ink mb-sm">
                {isAllCategory ? 'All category overview' : 'Category items'}
              </h3>
              <QueryStateView
                isLoading={loading}
                error={error}
                onRetry={() => (isAllCategory ? load() : loadCategoryItems(activeCategory))}
                isEmpty={itemsEmpty}
                emptyTitle="No items parsed"
                emptyDescription="Try another category or refresh."
              >
                {isAllCategory ? (
                  <GroupedHubItemsList groupedItems={groupedCategoryItems} />
                ) : (
                  <HubItemsList items={categoryItems} />
                )}
              </QueryStateView>
            </section>
          </TabsContent>

          <TabsContent value="manual" className="space-y-sm pt-sm">
            <section className="rounded-lg bg-surface-card p-md space-y-sm">
              <h3 className="font-display text-title-md text-ink">Manual apply YAML</h3>
              <p className="text-caption text-muted">
                Applies via <span className="font-mono">/api/hub/:category/manual-apply</span>.
              </p>
              <ButtonPrimary onClick={() => setShowManualDialog(true)} disabled={isAllCategory}>
                <Wrench className="h-4 w-4 mr-1" />
                Open manual apply
              </ButtonPrimary>
              {isAllCategory && (
                <p className="text-caption text-muted">Choose a specific category before applying YAML.</p>
              )}
            </section>
          </TabsContent>

          <TabsContent value="prefs" className="space-y-sm pt-sm">
            <section className="rounded-lg border border-hairline bg-canvas p-md">
              <div className="font-display text-title-md text-ink mb-sm">Preferences</div>
              {preferences.length === 0 ? (
                <p className="text-caption text-muted">No preferences configured.</p>
              ) : (
                <div className="space-y-xxs">
                  {preferences.map((pref) => (
                    <div
                      key={pref.category}
                      className="flex items-center justify-between py-sm border-b border-hairline-soft last:border-0"
                    >
                      <span className="text-body-md text-ink">{pref.category}</span>
                      <Pill tone={pref.default_mode === 'direct' ? 'coral' : 'cream'}>{pref.default_mode}</Pill>
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="rounded-lg bg-surface-card p-md space-y-sm">
              <h3 className="font-display text-title-md text-ink">Edit active category</h3>
              {activePreference ? (
                <>
                  <div className="flex gap-xs">
                    <ModeButton
                      active={activePreference.default_mode === 'direct'}
                      onClick={() => setActivePreference((prev) => (prev ? { ...prev, default_mode: 'direct' } : prev))}
                    >
                      Direct
                    </ModeButton>
                    <ModeButton
                      active={activePreference.default_mode === 'manual'}
                      onClick={() => setActivePreference((prev) => (prev ? { ...prev, default_mode: 'manual' } : prev))}
                    >
                      Manual
                    </ModeButton>
                  </div>
                  <Input
                    placeholder="Default YAML path"
                    value={activePreference.default_yaml_path || ''}
                    onChange={(e) =>
                      setActivePreference((prev) => (prev ? { ...prev, default_yaml_path: e.target.value } : prev))
                    }
                  />
                  <Input
                    placeholder="Last item name"
                    value={activePreference.last_item_name || ''}
                    onChange={(e) =>
                      setActivePreference((prev) => (prev ? { ...prev, last_item_name: e.target.value } : prev))
                    }
                  />
                  <ButtonPrimary size="sm" onClick={savePreference} disabled={actionLoading}>
                    <Save className="h-4 w-4 mr-1" />
                    Save preference
                  </ButtonPrimary>
                </>
              ) : (
                <p className="text-caption text-muted">Select a specific category to load preference data.</p>
              )}
            </section>
          </TabsContent>

          <TabsContent value="history" className="space-y-sm pt-sm">
            <section className="rounded-lg bg-surface-card p-md space-y-sm">
              <h3 className="font-display text-title-md text-ink">Inspect history record</h3>
              <div className="flex gap-xs">
                <Input
                  placeholder="History ID"
                  value={historyInspectId}
                  onChange={(e) => setHistoryInspectId(e.target.value)}
                />
                <ButtonPrimary
                  size="sm"
                  onClick={inspectHistory}
                  disabled={!historyInspectId.trim() || actionLoading}
                >
                  <History className="h-4 w-4 mr-1" />
                  Inspect
                </ButtonPrimary>
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
        <Input
          placeholder="Filename (e.g. custom.yaml)"
          value={manualFilename}
          onChange={(e) => setManualFilename(e.target.value)}
        />
        <Input
          placeholder="Target path (optional)"
          value={manualTargetPath}
          onChange={(e) => setManualTargetPath(e.target.value)}
        />
        <Textarea
          placeholder="YAML content"
          value={manualYaml}
          onChange={(e) => setManualYaml(e.target.value)}
          className="min-h-[200px] font-mono text-code"
        />
      </FormDialog>
    </div>
  );
}

function CategoryPill({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'px-sm py-xxs rounded-pill text-button font-medium transition-colors whitespace-nowrap',
        active ? 'bg-primary text-on-primary' : 'bg-canvas text-muted border border-hairline hover:text-ink',
      )}
    >
      {children}
    </button>
  );
}

function ModeButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'h-9 px-md rounded-md text-button font-medium transition-colors',
        active ? 'bg-primary text-on-primary' : 'bg-canvas text-ink border border-hairline',
      )}
    >
      {children}
    </button>
  );
}

function HubItemsList({ items }: { items: HubCategoryItem[] }) {
  return (
    <div className="max-h-[40vh] overflow-y-auto">
      <div className="space-y-xs">
        {items.map((item, i) => {
          const obj = typeof item === 'object' && item !== null ? (item as Record<string, unknown>) : null;
          if (!obj) return <div key={i} className="text-caption text-muted">{String(item)}</div>;

          const name = String(obj.name || obj.Name || obj.title || `Item ${i + 1}`);
          const version = obj.version || obj.local_version;
          const status = obj.status || (obj.installed ? 'installed' : 'available');
          const installed = String(status) === 'installed' || String(status) === 'enabled';

          return (
            <div key={name + i} className="rounded-md bg-canvas border border-hairline-soft p-sm">
              <div className="flex items-center justify-between gap-sm">
                <span className="text-body-sm font-medium text-ink truncate">{name}</span>
                {status && <Pill tone={installed ? 'success' : 'outline'}>{String(status)}</Pill>}
              </div>
              {version && <span className="text-caption font-mono text-muted-soft">v{String(version)}</span>}
              {obj.description && <p className="text-caption text-muted truncate">{String(obj.description)}</p>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function GroupedHubItemsList({ groupedItems }: { groupedItems: Record<string, HubCategoryItem[]> }) {
  return (
    <div className="space-y-sm">
      {Object.entries(groupedItems)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([category, items]) => (
          <section key={category} className="rounded-md bg-canvas border border-hairline p-sm space-y-xs">
            <div className="flex items-center justify-between">
              <h4 className="text-caption-uppercase uppercase font-medium text-muted">{fmtKey(category)}</h4>
              <Pill tone="outline">{items.length}</Pill>
            </div>
            <HubItemsList items={items} />
          </section>
        ))}
    </div>
  );
}

function HistoryListPanel({ records }: { records: HubOperationRecord[] }) {
  if (records.length === 0) {
    return (
      <div className="rounded-lg bg-surface-card p-md">
        <h3 className="font-display text-title-md text-ink mb-xs">History</h3>
        <p className="text-caption text-muted">No operation history.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg bg-surface-card p-md space-y-xs">
      <div className="flex items-center justify-between">
        <h3 className="font-display text-title-md text-ink">History</h3>
        <Pill tone="outline">{records.length}</Pill>
      </div>
      <div className="max-h-[40vh] overflow-y-auto">
        <div className="space-y-xs">
          {records.map((record) => (
            <div key={record.id} className="rounded-md bg-canvas border border-hairline-soft p-sm">
              <div className="flex items-center gap-xs">
                <Dot tone={record.success ? 'success' : 'error'} />
                <span className="text-body-sm font-medium text-ink">{record.action}</span>
                <span className="text-caption text-muted">·</span>
                <span className="text-caption text-muted">{record.category}</span>
                <Pill tone="outline" className="ml-auto">
                  #{record.id}
                </Pill>
              </div>
              {record.item_name && <p className="text-caption text-ink truncate mt-xxs">{record.item_name}</p>}
              {record.created_at && (
                <p className="text-caption text-muted-soft mt-xxs">{relativeTime(record.created_at)}</p>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function HistoryDetailCard({ record }: { record: HubOperationRecord }) {
  return (
    <div className="rounded-lg border border-hairline bg-canvas p-md space-y-sm">
      <div className="flex items-center justify-between">
        <h3 className="font-display text-title-md text-ink">History #{record.id}</h3>
        <Pill tone={record.success ? 'success' : 'error'}>{record.success ? 'Success' : 'Failed'}</Pill>
      </div>
      <dl className="grid grid-cols-2 gap-x-sm gap-y-xxs text-caption">
        <DescTerm label="Action" value={record.action} />
        <DescTerm label="Category" value={record.category} />
        <DescTerm label="Mode" value={record.mode} />
        {record.item_name && <DescTerm label="Item" value={record.item_name} />}
        {record.yaml_path && <DescTerm label="Path" value={record.yaml_path} mono />}
        {record.created_at && <DescTerm label="When" value={relativeTime(record.created_at)} />}
      </dl>
      {record.command && (
        <div className="rounded-md bg-surface-dark text-on-dark p-sm font-mono text-code overflow-x-auto">
          {record.command}
        </div>
      )}
      {record.error && (
        <div className="rounded-md bg-error/10 border border-error/20 p-sm">
          <h4 className="text-caption-uppercase uppercase font-medium text-error mb-xxs">Error</h4>
          <pre className="text-caption font-mono whitespace-pre-wrap text-error">{record.error}</pre>
        </div>
      )}
    </div>
  );
}

function DescTerm({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <>
      <dt className="text-muted">{label}</dt>
      <dd className={cn('text-ink', mono && 'font-mono')}>{value}</dd>
    </>
  );
}

function fmtKey(key: string): string {
  return key
    .replace(/_/g, ' ')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}
