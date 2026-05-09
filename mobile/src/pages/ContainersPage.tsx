import { useCallback, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { useApi } from '@/contexts/ApiContext';
import { TopBar } from '@/components/TopBar';
import { PullToRefresh } from '@/components/PullToRefresh';
import { QueryStateView } from '@/components/QueryStateView';
import { ConfirmActionDialog } from '@/components/ConfirmActionDialog';
import { ButtonPrimary, ButtonSecondary, Dot, Pill } from '@/components/design';
import { showActionError, showActionSuccess } from '@/lib/actionToast';
import type { HealthContainer } from '@/lib/api';

type ContainerAction = { container: string; action: 'start' | 'stop' | 'restart' };

async function triggerHaptics() {
  try {
    const { Haptics, ImpactStyle } = await import('@capacitor/haptics');
    await Haptics.impact({ style: ImpactStyle.Medium });
  } catch {
    /* PWA fallback */
  }
}

export default function ContainersPage() {
  const { api } = useApi();
  const [containers, setContainers] = useState<HealthContainer[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<ContainerAction | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  const fetchContainers = useCallback(async () => {
    if (!api) return;
    setLoading(true);
    setError(null);
    try {
      const stack = await api.health.getStack();
      setContainers(stack?.containers ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load containers');
    } finally {
      setLoading(false);
    }
  }, [api]);

  useMountEffect(() => {
    fetchContainers();
  });

  const confirmAction = useCallback(async () => {
    if (!api || !pendingAction) return;
    setActionLoading(true);
    try {
      await triggerHaptics();
      await api.services.action(pendingAction.container, pendingAction.action);
      showActionSuccess(
        `Container ${pendingAction.action}`,
        `${pendingAction.container} — ${pendingAction.action} successful`,
      );
      setPendingAction(null);
      await fetchContainers();
    } catch (err) {
      showActionError(`Failed to ${pendingAction.action}`, err);
    } finally {
      setActionLoading(false);
    }
  }, [api, pendingAction, fetchContainers]);

  const runningCount = containers.filter((c) => c.running).length;
  const total = containers.length;

  return (
    <PullToRefresh onRefresh={fetchContainers}>
      <div className="pb-nav bg-canvas">
        <TopBar
          title="Containers"
          right={<Pill tone={runningCount === total ? 'success' : 'warning'}>{`${runningCount} / ${total}`}</Pill>}
        />

        <div className="px-md py-md space-y-sm">
          <QueryStateView
            isLoading={loading}
            error={error}
            onRetry={fetchContainers}
            isEmpty={containers.length === 0}
            emptyTitle="No containers found"
            emptyDescription="No Docker containers discovered. Check your Docker setup."
          >
            {containers.map((container) => (
              <div key={container.id || container.name} className="rounded-lg bg-surface-card p-md">
                <div className="flex items-center justify-between gap-sm">
                  <div className="flex items-center gap-xs min-w-0">
                    <Dot tone={container.running ? 'success' : 'error'} pulse={container.running} />
                    <span className="font-display text-title-md text-ink truncate">{container.name}</span>
                  </div>
                  <Pill tone={container.running ? 'success' : 'error'}>
                    {container.status || (container.running ? 'running' : 'stopped')}
                  </Pill>
                </div>
                <div className="mt-xs grid grid-cols-2 gap-sm text-caption text-muted">
                  <span>
                    id <span className="font-mono text-ink">{container.id?.slice(0, 12) || '—'}</span>
                  </span>
                  <span>
                    state <span className="font-mono text-ink">{container.running ? 'up' : 'down'}</span>
                  </span>
                </div>
                <div className="mt-md flex gap-xs flex-wrap">
                  <ButtonSecondary
                    size="sm"
                    onClick={() => setPendingAction({ container: container.name, action: 'restart' })}
                    disabled={!container.running}
                  >
                    Restart
                  </ButtonSecondary>
                  {container.running ? (
                    <ButtonSecondary
                      size="sm"
                      onClick={() => setPendingAction({ container: container.name, action: 'stop' })}
                    >
                      Stop
                    </ButtonSecondary>
                  ) : (
                    <ButtonSecondary
                      size="sm"
                      onClick={() => setPendingAction({ container: container.name, action: 'start' })}
                    >
                      Start
                    </ButtonSecondary>
                  )}
                  <ButtonPrimary size="sm" disabled={!container.running}>
                    Shell
                  </ButtonPrimary>
                </div>
              </div>
            ))}
          </QueryStateView>
        </div>

        <ConfirmActionDialog
          open={!!pendingAction}
          onOpenChange={(open) => {
            if (!open) setPendingAction(null);
          }}
          title={`${pendingAction?.action ? pendingAction.action.charAt(0).toUpperCase() + pendingAction.action.slice(1) : ''} Container`}
          description={`Are you sure you want to ${pendingAction?.action} "${pendingAction?.container}"?`}
          confirmLabel={
            pendingAction?.action
              ? pendingAction.action.charAt(0).toUpperCase() + pendingAction.action.slice(1)
              : 'Confirm'
          }
          destructive={pendingAction?.action === 'stop'}
          loading={actionLoading}
          onConfirm={confirmAction}
        />
      </div>
    </PullToRefresh>
  );
}
