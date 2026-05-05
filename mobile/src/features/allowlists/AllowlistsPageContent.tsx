import { useCallback, useMemo, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { Eye, Trash2, Clock } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { TopBar } from '@/components/TopBar';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { QueryStateView } from '@/components/QueryStateView';
import { ConfirmActionDialog } from '@/components/ConfirmActionDialog';
import { FormDialog } from '@/components/FormDialog';
import { ButtonPrimary, ButtonSecondary, Pill, UpperBadge } from '@/components/design';
import { showActionError, showActionSuccess } from '@/lib/actionToast';
import { cn } from '@/lib/utils';
import type { Allowlist, AllowlistInspectResponse, AllowlistEntry } from '@/lib/api';

const EMERGENCY_HINTS = ['emergency', 'break-glass', 'breakglass', 'ops'];

function isEmergencyList(name: string, description?: string) {
  const lower = `${name} ${description ?? ''}`.toLowerCase();
  return EMERGENCY_HINTS.some((hint) => lower.includes(hint));
}

export default function AllowlistsPage() {
  const { api } = useApi();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lists, setLists] = useState<Allowlist[]>([]);
  const [inspected, setInspected] = useState<AllowlistInspectResponse | null>(null);

  const [showCreate, setShowCreate] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createDescription, setCreateDescription] = useState('');

  const [activeListName, setActiveListName] = useState('');
  const [entriesInput, setEntriesInput] = useState('');
  const [expirationInput, setExpirationInput] = useState('');
  const [entryDescription, setEntryDescription] = useState('');
  const [showAddEntries, setShowAddEntries] = useState(false);
  const [showRemoveEntries, setShowRemoveEntries] = useState(false);

  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  const load = useCallback(async () => {
    if (!api) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.allowlist.list();
      setLists(res?.allowlists || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load allowlists');
      setLists([]);
    } finally {
      setLoading(false);
    }
  }, [api]);

  useMountEffect(() => {
    load();
  });

  const parsedEntries = useMemo(
    () => entriesInput.split(',').map((entry) => entry.trim()).filter(Boolean),
    [entriesInput],
  );

  const inspect = async (name: string) => {
    if (!api) return;
    setActionLoading(true);
    try {
      const details = await api.allowlist.inspect(name);
      setInspected(details);
      showActionSuccess('Allowlist loaded', name);
    } catch (err) {
      showActionError('Failed to inspect allowlist', err);
    } finally {
      setActionLoading(false);
    }
  };

  const createAllowlist = async () => {
    if (!api) return;
    setActionLoading(true);
    try {
      const res = await api.allowlist.create({
        name: createName.trim(),
        description: createDescription.trim(),
      });
      showActionSuccess('Allowlist created', res.message || createName.trim());
      setCreateName('');
      setCreateDescription('');
      setShowCreate(false);
      await load();
    } catch (err) {
      showActionError('Failed to create allowlist', err);
    } finally {
      setActionLoading(false);
    }
  };

  const addEntries = async () => {
    if (!api || !activeListName || parsedEntries.length === 0) return;
    setActionLoading(true);
    try {
      const res = await api.allowlist.addEntries({
        allowlist_name: activeListName,
        values: parsedEntries,
        expiration: expirationInput.trim() || undefined,
        description: entryDescription.trim() || undefined,
      });
      showActionSuccess('Entries added', res.message || activeListName);
      resetEntryForms();
      setShowAddEntries(false);
      await load();
      await inspect(activeListName);
    } catch (err) {
      showActionError('Failed to add entries', err);
    } finally {
      setActionLoading(false);
    }
  };

  const removeEntries = async () => {
    if (!api || !activeListName || parsedEntries.length === 0) return;
    setActionLoading(true);
    try {
      const res = await api.allowlist.removeEntries({
        allowlist_name: activeListName,
        values: parsedEntries,
      });
      showActionSuccess('Entries removed', res.message || activeListName);
      resetEntryForms();
      setShowRemoveEntries(false);
      await load();
      await inspect(activeListName);
    } catch (err) {
      showActionError('Failed to remove entries', err);
    } finally {
      setActionLoading(false);
    }
  };

  const deleteAllowlist = async () => {
    if (!api || !deleteTarget) return;
    setActionLoading(true);
    try {
      const res = await api.allowlist.delete(deleteTarget);
      showActionSuccess('Allowlist deleted', res.message || deleteTarget);
      if (inspected?.name === deleteTarget) setInspected(null);
      setDeleteTarget(null);
      await load();
    } catch (err) {
      showActionError('Failed to delete allowlist', err);
    } finally {
      setActionLoading(false);
    }
  };

  const openEntryDialog = (name: string, mode: 'add' | 'remove') => {
    setActiveListName(name);
    resetEntryForms();
    if (mode === 'add') setShowAddEntries(true);
    else setShowRemoveEntries(true);
  };

  const resetEntryForms = () => {
    setEntriesInput('');
    setExpirationInput('');
    setEntryDescription('');
  };

  return (
    <div className="pb-nav bg-canvas">
      <TopBar
        title="Allowlists"
        right={
          <ButtonPrimary size="sm" onClick={() => setShowCreate(true)}>
            + New
          </ButtonPrimary>
        }
      />

      <div className="px-md py-md space-y-sm">
        <QueryStateView
          isLoading={loading}
          error={error}
          onRetry={load}
          isEmpty={lists.length === 0}
          emptyTitle="No allowlists found"
          emptyDescription="Create one to begin adding trusted IPs and ranges."
        >
          {lists.map((list) => {
            const coral = isEmergencyList(list.name, list.description);
            const entryCount = list.size ?? list.items?.length ?? 0;
            return (
              <div key={list.name} className={cn('rounded-lg p-md', coral ? 'bg-primary text-on-primary' : 'bg-surface-card text-ink')}>
                <div className="flex items-center justify-between gap-sm">
                  <div className="font-display text-title-md truncate">{list.name}</div>
                  <UpperBadge tone={coral ? 'cream' : 'coral'}>{entryCount} entries</UpperBadge>
                </div>
                <p className={cn('mt-xxs text-body-sm', coral ? 'opacity-90' : 'text-muted')}>
                  {list.description || 'No description'}
                </p>
                <div className="mt-md flex flex-wrap gap-xs">
                  <ButtonSecondary
                    size="sm"
                    dark={coral}
                    onClick={() => inspect(list.name)}
                    disabled={actionLoading}
                  >
                    <Eye className="h-3.5 w-3.5 mr-1" />
                    Inspect
                  </ButtonSecondary>
                  <ButtonSecondary size="sm" dark={coral} onClick={() => openEntryDialog(list.name, 'add')}>
                    Add entries
                  </ButtonSecondary>
                  <ButtonSecondary size="sm" dark={coral} onClick={() => openEntryDialog(list.name, 'remove')}>
                    Remove entries
                  </ButtonSecondary>
                  <button
                    onClick={() => setDeleteTarget(list.name)}
                    className={cn(
                      'h-9 px-md rounded-md inline-flex items-center justify-center transition-colors',
                      coral ? 'text-on-primary hover:bg-on-primary/10' : 'text-error hover:bg-error/10',
                    )}
                    aria-label="Delete allowlist"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            );
          })}

          <div className="rounded-lg border border-dashed border-hairline p-md text-center">
            <div className="font-display text-title-md text-ink">Import a CIDR set</div>
            <p className="text-body-sm text-muted mt-xxs">
              Paste a CSV of IPs or ranges to bulk-add via &quot;Add entries&quot; on a list.
            </p>
            <div className="mt-sm">
              <ButtonSecondary onClick={() => setShowCreate(true)}>Create allowlist first</ButtonSecondary>
            </div>
          </div>
        </QueryStateView>

        {inspected && <AllowlistDetailPanel inspected={inspected} />}
      </div>

      <FormDialog
        open={showCreate}
        onOpenChange={setShowCreate}
        title="Create allowlist"
        description="POST /api/allowlist/create"
        submitLabel="Create"
        loading={actionLoading}
        onSubmit={createAllowlist}
      >
        <Input placeholder="Name" value={createName} onChange={(e) => setCreateName(e.target.value)} />
        <Input
          placeholder="Description"
          value={createDescription}
          onChange={(e) => setCreateDescription(e.target.value)}
        />
      </FormDialog>

      <FormDialog
        open={showAddEntries}
        onOpenChange={setShowAddEntries}
        title={`Add entries: ${activeListName}`}
        description="Comma-separated values"
        submitLabel="Add"
        loading={actionLoading}
        onSubmit={addEntries}
      >
        <Input
          placeholder="1.2.3.4, 10.0.0.0/8"
          value={entriesInput}
          onChange={(e) => setEntriesInput(e.target.value)}
        />
        <Input
          placeholder="Expiration (optional, e.g. 7d)"
          value={expirationInput}
          onChange={(e) => setExpirationInput(e.target.value)}
        />
        <Input
          placeholder="Description (optional)"
          value={entryDescription}
          onChange={(e) => setEntryDescription(e.target.value)}
        />
      </FormDialog>

      <FormDialog
        open={showRemoveEntries}
        onOpenChange={setShowRemoveEntries}
        title={`Remove entries: ${activeListName}`}
        description="Comma-separated values to remove"
        submitLabel="Remove"
        loading={actionLoading}
        onSubmit={removeEntries}
      >
        <Input
          placeholder="1.2.3.4, 10.0.0.0/8"
          value={entriesInput}
          onChange={(e) => setEntriesInput(e.target.value)}
        />
      </FormDialog>

      <ConfirmActionDialog
        open={Boolean(deleteTarget)}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null);
        }}
        title="Delete allowlist?"
        description={`Allowlist ${deleteTarget || ''} will be deleted.`}
        confirmLabel="Delete"
        destructive
        loading={actionLoading}
        onConfirm={deleteAllowlist}
      />
    </div>
  );
}

function AllowlistDetailPanel({ inspected }: { inspected: AllowlistInspectResponse }) {
  return (
    <div className="rounded-lg border border-hairline bg-canvas p-md space-y-sm">
      <div className="flex items-start justify-between gap-sm">
        <div>
          <h3 className="font-display text-title-md text-ink">{inspected.name}</h3>
          {inspected.description && <p className="text-caption text-muted">{inspected.description}</p>}
        </div>
        <Pill tone="cream">{inspected.count} entries</Pill>
      </div>

      {inspected.created_at && (
        <p className="text-caption text-muted-soft">
          Created · {new Date(inspected.created_at).toLocaleDateString()}
          {inspected.updated_at && ` · Updated · ${new Date(inspected.updated_at).toLocaleDateString()}`}
        </p>
      )}

      <Separator />

      {inspected.items.length > 0 ? (
        <ScrollArea className="max-h-[40vh]">
          <div className="space-y-xs">
            {inspected.items.map((entry: AllowlistEntry, i: number) => (
              <div
                key={entry.value + i}
                className="rounded-md bg-surface-card p-sm flex items-center justify-between gap-sm"
              >
                <span className="font-mono text-body-sm text-ink truncate">{entry.value}</span>
                {entry.expiration ? (
                  <Pill tone="warning">
                    <Clock className="h-2.5 w-2.5" />
                    {entry.expiration}
                  </Pill>
                ) : (
                  <Pill tone="outline">Permanent</Pill>
                )}
              </div>
            ))}
          </div>
        </ScrollArea>
      ) : (
        <p className="text-caption text-muted">No entries in this allowlist.</p>
      )}
    </div>
  );
}
