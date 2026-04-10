import { useCallback, useMemo, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { Eye, Plus, RefreshCw, Trash2, Clock } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { PageHeader } from '@/components/PageHeader';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { QueryStateView } from '@/components/QueryStateView';
import { ConfirmActionDialog } from '@/components/ConfirmActionDialog';
import { FormDialog } from '@/components/FormDialog';
import { MetricCard } from '@/components/MetricCard';
import { showActionError, showActionSuccess } from '@/lib/actionToast';
import type { Allowlist, AllowlistInspectResponse, AllowlistEntry } from '@/lib/api';

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
    () =>
      entriesInput
        .split(',')
        .map((entry) => entry.trim())
        .filter(Boolean),
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
      const res = await api.allowlist.create({ name: createName.trim(), description: createDescription.trim() });
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
      if (inspected?.name === deleteTarget) {
        setInspected(null);
      }
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
    if (mode === 'add') {
      setShowAddEntries(true);
      return;
    }
    setShowRemoveEntries(true);
  };

  const resetEntryForms = () => {
    setEntriesInput('');
    setExpirationInput('');
    setEntryDescription('');
  };

  return (
    <div className="pb-nav">
      <PageHeader
        title="Allowlists"
        subtitle="Manage CrowdSec allowlists"
        action={
          <div className="flex gap-1">
            <Button variant="ghost" size="icon" onClick={load} disabled={loading}>
              <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
            </Button>
            <Button size="sm" onClick={() => setShowCreate(true)}>
              <Plus className="h-4 w-4 mr-1" />
              Create
            </Button>
          </div>
        }
      />

      <div className="px-4 space-y-3">
        <QueryStateView
          isLoading={loading}
          error={error}
          onRetry={load}
          isEmpty={lists.length === 0}
          emptyTitle="No allowlists found"
          emptyDescription="Create one to begin adding trusted IPs and ranges."
        >
          {lists.map((list) => (
            <div key={list.name} className="rounded-xl border border-border bg-card p-4 space-y-3">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <h3 className="text-sm font-semibold">{list.name}</h3>
                  <p className="text-xs text-muted-foreground">{list.description || 'No description'}</p>
                  <p className="text-[11px] text-muted-foreground mt-1">Entries: {list.size ?? list.items?.length ?? 0}</p>
                </div>
                <div className="flex gap-1">
                  <Button variant="ghost" size="icon" onClick={() => inspect(list.name)} disabled={actionLoading}>
                    <Eye className="h-4 w-4" />
                  </Button>
                  <Button variant="ghost" size="icon" onClick={() => setDeleteTarget(list.name)}>
                    <Trash2 className="h-4 w-4 text-destructive" />
                  </Button>
                </div>
              </div>
              <div className="flex gap-2">
                <Button variant="secondary" size="sm" onClick={() => openEntryDialog(list.name, 'add')}>
                  Add entries
                </Button>
                <Button variant="secondary" size="sm" onClick={() => openEntryDialog(list.name, 'remove')}>
                  Remove entries
                </Button>
              </div>
            </div>
          ))}
        </QueryStateView>

        {/* Inspected Allowlist Details */}
        {inspected && <AllowlistDetailPanel inspected={inspected} />}
      </div>

      <FormDialog open={showCreate} onOpenChange={setShowCreate} title="Create allowlist" description="POST /api/allowlist/create" submitLabel="Create" loading={actionLoading} onSubmit={createAllowlist}>
        <Input placeholder="Name" value={createName} onChange={(e) => setCreateName(e.target.value)} />
        <Input placeholder="Description" value={createDescription} onChange={(e) => setCreateDescription(e.target.value)} />
      </FormDialog>

      <FormDialog open={showAddEntries} onOpenChange={setShowAddEntries} title={`Add entries: ${activeListName}`} description="Comma-separated values" submitLabel="Add" loading={actionLoading} onSubmit={addEntries}>
        <Input placeholder="1.2.3.4, 10.0.0.0/8" value={entriesInput} onChange={(e) => setEntriesInput(e.target.value)} />
        <Input placeholder="Expiration (optional, e.g. 7d)" value={expirationInput} onChange={(e) => setExpirationInput(e.target.value)} />
        <Input placeholder="Description (optional)" value={entryDescription} onChange={(e) => setEntryDescription(e.target.value)} />
      </FormDialog>

      <FormDialog open={showRemoveEntries} onOpenChange={setShowRemoveEntries} title={`Remove entries: ${activeListName}`} description="Comma-separated values to remove" submitLabel="Remove" loading={actionLoading} onSubmit={removeEntries}>
        <Input placeholder="1.2.3.4, 10.0.0.0/8" value={entriesInput} onChange={(e) => setEntriesInput(e.target.value)} />
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

/* ────────────────────── Allowlist Detail Panel ────────────────────── */

function AllowlistDetailPanel({ inspected }: { inspected: AllowlistInspectResponse }) {
  return (
    <div className="rounded-xl border border-border bg-card p-4 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold">{inspected.name}</h3>
          {inspected.description && (
            <p className="text-xs text-muted-foreground">{inspected.description}</p>
          )}
        </div>
        <MetricCard label="Entries" value={inspected.count} className="w-24" />
      </div>

      {inspected.created_at && (
        <p className="text-[10px] text-muted-foreground">
          Created: {new Date(inspected.created_at).toLocaleDateString()}
          {inspected.updated_at && ` · Updated: ${new Date(inspected.updated_at).toLocaleDateString()}`}
        </p>
      )}

      <Separator />

      {inspected.items.length > 0 ? (
        <ScrollArea className="max-h-[40vh]">
          <div className="space-y-2">
            {inspected.items.map((entry: AllowlistEntry, i: number) => (
              <div key={entry.value + i} className="rounded-lg border border-border/50 bg-muted/30 p-3 space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium font-mono truncate">{entry.value}</span>
                  {entry.expiration ? (
                    <Badge variant="warning" className="text-[10px] shrink-0">
                      <Clock className="h-2.5 w-2.5 mr-1" />
                      {entry.expiration}
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="text-[10px] shrink-0">Permanent</Badge>
                  )}
                </div>
                {entry.created_at && (
                  <p className="text-[10px] text-muted-foreground">
                    Added: {new Date(entry.created_at).toLocaleDateString()}
                  </p>
                )}
              </div>
            ))}
          </div>
        </ScrollArea>
      ) : (
        <p className="text-xs text-muted-foreground">No entries in this allowlist.</p>
      )}
    </div>
  );
}
