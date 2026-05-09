import { useCallback, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { Trash2 } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { TopBar } from '@/components/TopBar';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { QueryStateView } from '@/components/QueryStateView';
import { ConfirmActionDialog } from '@/components/ConfirmActionDialog';
import { FormDialog } from '@/components/FormDialog';
import { ButtonPrimary, Pill } from '@/components/design';
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
        scenarios: [{ name: newName.trim(), description: newDescription.trim(), content: newContent }],
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

  const featuredScenario = scenarios[0];
  const featuredYaml = files[0];

  return (
    <div className="pb-nav bg-canvas">
      <TopBar
        title="Scenarios"
        right={<Pill tone="cream">{scenarios.length} active</Pill>}
      />

      <div className="px-md py-md space-y-md">
        <QueryStateView
          isLoading={loading}
          error={error}
          onRetry={load}
          isEmpty={scenarios.length === 0 && files.length === 0}
          emptyTitle="No scenarios listed"
          emptyDescription="Refresh after setup or check CrowdSec status."
        >
          {/* YAML callout — first installed scenario */}
          {featuredScenario && (
            <div className="rounded-lg bg-surface-dark text-on-dark p-md font-mono text-code">
              <div className="text-on-dark-soft mb-xs flex items-center justify-between">
                <span className="truncate">{featuredScenario.name}.yaml</span>
                <Pill tone="teal">{featuredScenario.status || 'enabled'}</Pill>
              </div>
              <YamlLine k="type" v={(featuredScenario as { type?: string }).type || 'leaky'} />
              <YamlLine k="name" v={featuredScenario.name} />
              <YamlLine k="version" v={featuredScenario.version || featuredScenario.local_version || 'n/a'} />
              {featuredScenario.description && <YamlLine k="description" v={`"${featuredScenario.description}"`} />}
            </div>
          )}

          {/* Custom YAML file preview */}
          {featuredYaml && (
            <div className="rounded-lg bg-surface-dark-elevated text-on-dark p-md font-mono text-code">
              <div className="text-on-dark-soft mb-xs flex items-center justify-between">
                <span className="truncate">{featuredYaml.filename}</span>
                <Pill tone="cream">custom</Pill>
              </div>
              <p className="text-on-dark/90 text-caption">{featuredYaml.description || featuredYaml.name || 'No metadata'}</p>
            </div>
          )}

          <div className="flex items-center justify-between">
            <div className="font-display text-title-md text-ink">Installed scenarios</div>
            <ButtonPrimary size="sm" onClick={() => setShowSetupDialog(true)}>
              + Setup
            </ButtonPrimary>
          </div>

          <div className="space-y-xs">
            {scenarios.map((scenario) => (
              <div key={scenario.name} className="rounded-md bg-surface-card flex items-center justify-between px-md py-sm gap-sm">
                <div className="min-w-0">
                  <span className="font-mono text-body-sm text-ink truncate block">{scenario.name}</span>
                  {scenario.description && (
                    <span className="text-caption text-muted truncate block">{scenario.description}</span>
                  )}
                </div>
                <Pill tone="success">{scenario.status || 'enabled'}</Pill>
              </div>
            ))}
          </div>

          {files.length > 0 && (
            <>
              <div className="font-display text-title-md text-ink mt-md">Custom files</div>
              <div className="space-y-xs">
                {files.map((file) => (
                  <div
                    key={file.filename}
                    className="rounded-md bg-surface-card flex items-center justify-between px-md py-sm gap-sm"
                  >
                    <div className="min-w-0">
                      <div className="font-mono text-body-sm text-ink truncate">{file.filename}</div>
                      <div className="text-caption text-muted truncate">
                        {file.description || file.name || 'No metadata'}
                      </div>
                    </div>
                    <button
                      onClick={() => setDeleteFilename(file.filename)}
                      className="w-8 h-8 inline-flex items-center justify-center text-error hover:bg-error/10 rounded-md transition-colors"
                      aria-label="Delete scenario file"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                ))}
              </div>
            </>
          )}
        </QueryStateView>
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
        <Input
          placeholder="Scenario name (e.g. crowdsecurity/custom-test)"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
        />
        <Input
          placeholder="Description"
          value={newDescription}
          onChange={(e) => setNewDescription(e.target.value)}
        />
        <Textarea
          placeholder="Scenario YAML content"
          value={newContent}
          onChange={(e) => setNewContent(e.target.value)}
          className="min-h-[180px] font-mono text-code"
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

function YamlLine({ k, v }: { k: string; v: string }) {
  return (
    <div>
      <span className="text-accent-amber">{k}</span>
      <span className="text-on-dark">: {v}</span>
    </div>
  );
}
