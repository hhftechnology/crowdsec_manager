import { useCallback, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { TerminalSquare } from 'lucide-react';
import '@xterm/xterm/css/xterm.css';
import { useApi } from '@/contexts/ApiContext';
import { TopBar } from '@/components/TopBar';
import { QueryStateView } from '@/components/QueryStateView';
import { InlineErrorBanner } from '@/components/InlineErrorBanner';
import { useTerminal } from '@/hooks/useTerminal';
import { ButtonPrimary, ButtonSecondary, CategoryTab, Dot, Pill } from '@/components/design';
import { showActionError, showActionSuccess } from '@/lib/actionToast';
import type { HealthContainer } from '@/lib/api';

export default function TerminalPage() {
  const { api } = useApi();
  const [containers, setContainers] = useState<HealthContainer[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedContainer, setSelectedContainer] = useState('');

  const loadContainers = useCallback(async () => {
    if (!api) return;
    setLoading(true);
    setError(null);
    try {
      const stack = await api.health.getStack();
      const running = (stack?.containers || []).filter((c: HealthContainer) => c.running);
      setContainers(running);
      if (running.length > 0 && !selectedContainer) setSelectedContainer(running[0].name);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load containers');
    } finally {
      setLoading(false);
    }
  }, [api, selectedContainer]);

  useMountEffect(() => {
    loadContainers();
  });

  const getWebSocketUrl = useCallback(
    (container: string) => (api ? api.terminal.getWebSocketUrl(container) : ''),
    [api],
  );

  const { terminalRef, connected, reconnecting, connectionError, connect, disconnect, reconnect } = useTerminal({
    getWebSocketUrl,
    container: selectedContainer,
    onConnect: () => showActionSuccess('Terminal connected', selectedContainer),
    onDisconnect: () => showActionSuccess('Terminal disconnected'),
    onError: (msg) => showActionError('Terminal error', new Error(msg)),
  });

  const statusPill = connected ? (
    <Pill tone="success">
      <Dot tone="success" pulse /> connected
    </Pill>
  ) : reconnecting ? (
    <Pill tone="warning">
      <Dot tone="warning" pulse /> reconnecting
    </Pill>
  ) : (
    <Pill tone="error">
      <Dot tone="error" /> offline
    </Pill>
  );

  return (
    <div className="pb-nav bg-canvas h-full flex flex-col">
      <TopBar title="Terminal" right={statusPill} />

      <div className="px-md pt-md pb-xs">
        <div className="text-caption-uppercase uppercase text-muted">Container</div>
        <div className="text-title-md text-ink font-display truncate">{selectedContainer || '—'}</div>
      </div>

      <div className="px-md flex-1 pb-md flex flex-col">
        <QueryStateView
          isLoading={loading}
          error={error}
          isEmpty={containers.length === 0}
          onRetry={loadContainers}
          emptyTitle="No running containers"
          emptyDescription="No running containers found. Check your Docker setup."
        >
          <div className="flex gap-xs overflow-x-auto pb-xs mb-sm">
            {containers.map((c) => (
              <CategoryTab
                key={c.name}
                active={selectedContainer === c.name}
                onClick={() => {
                  if (connected) disconnect();
                  setSelectedContainer(c.name);
                }}
              >
                {c.name}
              </CategoryTab>
            ))}
          </div>

          <div className="flex items-center gap-xs mb-sm flex-wrap">
            <ButtonPrimary size="sm" onClick={connect} disabled={connected || reconnecting || !selectedContainer}>
              Connect
            </ButtonPrimary>
            <ButtonSecondary size="sm" onClick={disconnect} disabled={!connected && !reconnecting}>
              Disconnect
            </ButtonSecondary>
            {!connected && !reconnecting && connectionError && (
              <ButtonSecondary size="sm" onClick={reconnect}>
                Reconnect
              </ButtonSecondary>
            )}
          </div>

          {connectionError && !connected && !reconnecting && (
            <div className="mb-sm">
              <InlineErrorBanner title="Connection Error" message={connectionError} />
            </div>
          )}

          <div className="relative flex-1 min-h-[50vh]">
            <section
              ref={terminalRef}
              className="absolute inset-0 rounded-lg overflow-hidden bg-surface-dark p-md"
            />
            {!connected && !reconnecting && (
              <div className="absolute inset-0 flex items-center justify-center rounded-lg bg-surface-dark text-on-dark">
                <div className="text-center">
                  <TerminalSquare className="h-8 w-8 text-on-dark-soft mx-auto mb-xs opacity-60" />
                  <p className="text-body-sm text-on-dark-soft">Select a container and tap Connect</p>
                </div>
              </div>
            )}
          </div>
        </QueryStateView>
      </div>
    </div>
  );
}
