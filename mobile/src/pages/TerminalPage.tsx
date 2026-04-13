import { useCallback, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { RefreshCw, TerminalSquare, Plug, Unplug, RotateCw, Loader2 } from 'lucide-react';
import '@xterm/xterm/css/xterm.css';
import { useApi } from '@/contexts/ApiContext';
import { PageHeader } from '@/components/PageHeader';
import { Button } from '@/components/ui/button';
import { QueryStateView } from '@/components/QueryStateView';
import { InlineErrorBanner } from '@/components/InlineErrorBanner';
import { useTerminal } from '@/hooks/useTerminal';
import { showActionError, showActionSuccess } from '@/lib/actionToast';
import type { WebSocketUrlOptions } from '@/lib/api/client';
import type { HealthContainer } from '@/lib/api';

export default function TerminalPage() {
  const { api, connectionProfile } = useApi();
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
      if (running.length > 0 && !selectedContainer) {
        setSelectedContainer(running[0].name);
      }
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
    (container: string, options?: WebSocketUrlOptions) => {
      if (!api) return Promise.resolve('');
      return api.terminal.getWebSocketUrl(container, options);
    },
    [api],
  );

  const { terminalRef, connected, reconnecting, connectionError, connect, disconnect, reconnect } = useTerminal({
    getWebSocketUrl,
    container: selectedContainer,
    allowPreOpenAuthRefresh: connectionProfile?.mode === 'pangolin',
    onConnect: () => showActionSuccess('Terminal connected', selectedContainer),
    onDisconnect: () => showActionSuccess('Terminal disconnected'),
    onError: (msg) => showActionError('Terminal error', new Error(msg)),
  });

  return (
    <div className="pb-nav">
      <PageHeader
        title="Terminal"
        subtitle={connected ? 'Connected to ' + selectedContainer : reconnecting ? 'Reconnecting...' : 'Interactive container shell'}
        action={
          <Button variant="ghost" size="icon" onClick={loadContainers} disabled={loading}>
            <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
          </Button>
        }
      />

      <div className="px-4 space-y-4">
        <QueryStateView
          isLoading={loading}
          error={error}
          isEmpty={containers.length === 0}
          onRetry={loadContainers}
          emptyTitle="No running containers"
          emptyDescription="No running containers found. Check your Docker setup."
        >
          <section className="rounded-xl border border-border bg-card p-4 space-y-3">
            <h3 className="text-sm font-semibold">Select container</h3>
            <div className="flex gap-2 overflow-x-auto pb-1">
              {containers.map((c) => (
                <Button
                  key={c.name}
                  variant={selectedContainer === c.name ? 'default' : 'secondary'}
                  size="sm"
                  onClick={() => {
                    if (connected) disconnect();
                    setSelectedContainer(c.name);
                  }}
                  className="whitespace-nowrap"
                >
                  <TerminalSquare className="h-3.5 w-3.5 mr-1" />
                  {c.name}
                </Button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              <Button
                onClick={connect}
                disabled={connected || reconnecting || !selectedContainer}
                size="sm"
              >
                <Plug className="h-4 w-4 mr-1" />
                Connect
              </Button>
              <Button
                variant="secondary"
                onClick={disconnect}
                disabled={!connected && !reconnecting}
                size="sm"
              >
                <Unplug className="h-4 w-4 mr-1" />
                Disconnect
              </Button>
              {!connected && !reconnecting && connectionError && (
                <Button
                  variant="outline"
                  onClick={reconnect}
                  size="sm"
                >
                  <RotateCw className="h-4 w-4 mr-1" />
                  Reconnect
                </Button>
              )}
              <div className={'ml-auto flex items-center gap-1.5 text-xs ' + (connected ? 'text-success' : reconnecting ? 'text-warning' : 'text-muted-foreground')}>
                {reconnecting ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <span className={'inline-block h-2 w-2 rounded-full ' + (connected ? 'bg-success' : 'bg-muted-foreground')} />
                )}
                {connected ? 'Connected' : reconnecting ? 'Reconnecting' : 'Disconnected'}
              </div>
            </div>
          </section>

          {connectionError && !connected && !reconnecting && (
            <InlineErrorBanner title="Connection Error" message={connectionError} />
          )}

          <div className="relative">
            <section
              ref={terminalRef}
              className="rounded-xl border border-border overflow-hidden min-h-[50vh] bg-[hsl(var(--terminal-bg))]"
            />
            {!connected && !reconnecting && (
              <div className="absolute inset-0 flex items-center justify-center rounded-xl bg-[hsl(var(--terminal-bg))]">
                <div className="text-center">
                  <TerminalSquare className="h-8 w-8 text-muted-foreground mx-auto mb-2 opacity-50" />
                  <p className="text-sm text-muted-foreground">Select a container and tap Connect</p>
                </div>
              </div>
            )}
          </div>
        </QueryStateView>
      </div>
    </div>
  );
}
