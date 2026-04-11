import { useCallback, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { RefreshCw, Trash2, Plus } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { PageHeader } from '@/components/PageHeader';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { QueryStateView } from '@/components/QueryStateView';
import { ConfirmActionDialog } from '@/components/ConfirmActionDialog';
import { FormDialog } from '@/components/FormDialog';
import { showActionError, showActionSuccess } from '@/lib/actionToast';
import type { ScenarioFile, ScenarioItem } from '@/lib/api';

export default function ScenariosPage() {
  const { api } = useApi();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  const [scenarios, setScenarios] = useState<ScenarioItem[]>([]);
  const [files, setFiles] = useState<ScenarioFile[]>([]);

  const [showSetupDialog, setShowSetupDialog] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newContent, setNewContent] = useState('');

  const [deleteFilename, setDeleteFilename] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!api) return;

    setLoading(true);
    setError(null);

    try {
      const [scenarioList, fileList] = await Promise.all([api.scenarios.list(), api.scenarios.files()]);
      setScenarios(Array.isArray(scenarioList?.scenarios) ? scenarioList.scenarios : []);
      setFiles(Array.isArray(fileList) ? fileList : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load scenarios');
    } finally {
      setLoading(false);
    }
  }, [api]);

  useMountEffect(() => {
    load();
  });

  const setupScenario = async () => {
    if (!api || !newName.trim() || !newContent.trim()) return;

    setActionLoading(true);
    try {
      const res = await api.scenarios.setup({
        scenarios: [
          {
            name: newName.trim(),
            description: newDescription.trim(),
            content: newContent,
          },
        ],
      });
      showActionSuccess('Scenario setup complete', res.message || newName.trim());
      setShowSetupDialog(false);
      setNewName('');
      setNewDescription('');
      setNewContent('');
      await load();
    } catch (err) {
      showActionError('Failed to setup scenario', err);
    } finally {
      setActionLoading(false);
    }
  };

  const deleteScenarioFile = async () => {
    if (!api || !deleteFilename) return;

    setActionLoading(true);
    try {
      const res = await api.scenarios.deleteFile(deleteFilename);
      showActionSuccess('Scenario file deleted', res.message || deleteFilename);
      setDeleteFilename(null);
      await load();
    } catch (err) {
      showActionError('Failed to delete scenario file', err);
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="pb-nav">
      <PageHeader
        title="Scenarios"
        subtitle="Setup, list files, and remove custom files"
        action={
          <div className="flex gap-1">
            <Button variant="ghost" size="icon" onClick={load} disabled={loading}>
              <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
            </Button>
            <Button size="sm" onClick={() => setShowSetupDialog(true)}>
              <Plus className="h-4 w-4 mr-1" />
              Setup
            </Button>
          </div>
        }
      />

      <div className="px-4 space-y-4">
        <section className="rounded-xl border border-border bg-card p-4">
          <h3 className="text-sm font-semibold mb-2">Installed scenarios</h3>
          <QueryStateView
            isLoading={loading}
            error={error}
            onRetry={load}
            isEmpty={scenarios.length === 0}
            emptyTitle="No scenarios listed"
            emptyDescription="Refresh after setup or check CrowdSec status."
          >
            <div className="space-y-2">
              {scenarios.map((scenario) => (
                <div key={scenario.name} className="rounded-lg border border-border p-3">
                  <div className="text-sm font-semibold">{scenario.name}</div>
                  <div className="text-xs text-muted-foreground">{scenario.description || 'No description'}</div>
                  <div className="text-[11px] text-muted-foreground mt-1">
                    Status: {scenario.status || 'unknown'} · Version: {scenario.version || scenario.local_version || 'n/a'}
                  </div>
                </div>
              ))}
            </div>
          </QueryStateView>
        </section>

        <section className="rounded-xl border border-border bg-card p-4">
          <h3 className="text-sm font-semibold mb-2">Scenario files</h3>
          <QueryStateView
            isLoading={loading}
            error={error}
            onRetry={load}
            isEmpty={files.length === 0}
            emptyTitle="No scenario files"
            emptyDescription="No custom scenario file found in config directory."
          >
            <div className="space-y-2">
              {files.map((file) => (
                <div key={file.filename} className="rounded-lg border border-border p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <div className="text-sm font-semibold">{file.filename}</div>
                      <div className="text-xs text-muted-foreground">{file.description || file.name || 'No metadata'}</div>
                    </div>
                    <Button variant="ghost" size="icon" onClick={() => setDeleteFilename(file.filename)}>
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </QueryStateView>
        </section>
      </div>

      <FormDialog
        open={showSetupDialog}
        onOpenChange={setShowSetupDialog}
        title="Setup custom scenario"
        description="POST /api/scenarios/setup"
        submitLabel="Apply"
        loading={actionLoading}
        onSubmit={setupScenario}
      >
        <Input placeholder="Scenario name (e.g. crowdsecurity/custom-test)" value={newName} onChange={(e) => setNewName(e.target.value)} />
        <Input placeholder="Description" value={newDescription} onChange={(e) => setNewDescription(e.target.value)} />
        <Textarea
          placeholder="Scenario YAML content"
          value={newContent}
          onChange={(e) => setNewContent(e.target.value)}
          className="min-h-[180px]"
        />
      </FormDialog>

      <ConfirmActionDialog
        open={Boolean(deleteFilename)}
        onOpenChange={(open) => {
          if (!open) setDeleteFilename(null);
        }}
        title="Delete scenario file?"
        description={`${deleteFilename || ''} will be removed and CrowdSec will reload.`}
        confirmLabel="Delete"
        destructive
        loading={actionLoading}
        onConfirm={deleteScenarioFile}
      />
    </div>
  );
}
