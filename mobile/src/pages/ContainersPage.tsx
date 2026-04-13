import { useCallback, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { RefreshCw, Play, Square, RotateCw } from 'lucide-react';
import { useApi } from '@/contexts/ApiContext';
import { PageHeader } from '@/components/PageHeader';
import { PullToRefresh } from '@/components/PullToRefresh';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { QueryStateView } from '@/components/QueryStateView';
import { StatusDot } from '@/components/StatusDot';
import { ConfirmActionDialog } from '@/components/ConfirmActionDialog';
import { showActionError, showActionSuccess } from '@/lib/actionToast';
import type { HealthContainer } from '@/lib/api';

type ContainerAction = { container: string; action: 'start' | 'stop' | 'restart' };

async function triggerHaptics() {
  try {
    const { Haptics, ImpactStyle } = await import('@capacitor/haptics');
    await Haptics.impact({ style: ImpactStyle.Medium });
  } catch {
    // Haptics not available (web/PWA) — silently ignore
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

  return (
    <PullToRefresh onRefresh={fetchContainers}>
      <div className="pb-nav">
        <PageHeader
          title="Containers"
          subtitle="Manage Docker containers"
          action={
            <Button variant="ghost" size="icon" onClick={fetchContainers} disabled={loading}>
              <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
            </Button>
          }
        />

        <div className="px-4 space-y-3">
          <QueryStateView
            isLoading={loading}
            error={error}
            onRetry={fetchContainers}
            isEmpty={containers.length === 0}
            emptyTitle="No containers found"
            emptyDescription="No Docker containers discovered. Check your Docker setup."
          >
            {containers.map((container) => (
              <div
                key={container.id || container.name}
                className="rounded-xl border border-border bg-card p-4 space-y-3"
              >
                <div className="flex items-center gap-3">
                  <StatusDot
                    color={container.running ? 'success' : 'error'}
                    pulse={container.running}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-semibold truncate">{container.name}</div>
                    <div className="text-[10px] text-muted-foreground font-mono truncate">
                      {container.id?.slice(0, 12)}
                    </div>
                  </div>
                  <Badge variant={container.running ? 'success' : 'destructive'} className="shrink-0">
                    {container.status || (container.running ? 'running' : 'stopped')}
                  </Badge>
                </div>

                <div className="flex items-center gap-2 justify-end">
                  {container.running ? (
                    <>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() =>
                          setPendingAction({ container: container.name, action: 'stop' })
                        }
                      >
                        <Square className="h-3.5 w-3.5 mr-1" />
                        Stop
                      </Button>
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() =>
                          setPendingAction({ container: container.name, action: 'restart' })
                        }
                      >
                        <RotateCw className="h-3.5 w-3.5 mr-1" />
                        Restart
                      </Button>
                    </>
                  ) : (
                    <Button
                      size="sm"
                      onClick={() =>
                        setPendingAction({ container: container.name, action: 'start' })
                      }
                    >
                      <Play className="h-3.5 w-3.5 mr-1" />
                      Start
                    </Button>
                  )}
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
          confirmLabel={pendingAction?.action ? pendingAction.action.charAt(0).toUpperCase() + pendingAction.action.slice(1) : 'Confirm'}
          destructive={pendingAction?.action === 'stop'}
          loading={actionLoading}
          onConfirm={confirmAction}
        />
      </div>
    </PullToRefresh>
  );
}
