import { useCallback, useMemo, useRef, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { RefreshCw, Play, Square, Download } from 'lucide-react';
import { PageHeader } from '@/components/PageHeader';
import { useApi } from '@/contexts/ApiContext';
import { PullToRefresh } from '@/components/PullToRefresh';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { QueryStateView } from '@/components/QueryStateView';
import { MetricCard } from '@/components/MetricCard';
import { StatusDot } from '@/components/StatusDot';
import { showActionError, showActionSuccess } from '@/lib/actionToast';
import type { LogStats, StructuredLogEntry, StructuredLogsResponse } from '@/lib/api';

export default function LogsPage() {
  const { api } = useApi();
  const wsRef = useRef<WebSocket | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [service, setService] = useState('crowdsec');
  const [tail, setTail] = useState('200');
  const [logType, setLogType] = useState<'access' | 'error'>('access');

  const [logs, setLogs] = useState<string>('');
  const [advanced, setAdvanced] = useState<LogStats | null>(null);
  const [structured, setStructured] = useState<StructuredLogsResponse | null>(null);

  const [isStreaming, setIsStreaming] = useState(false);
  const [streamLogs, setStreamLogs] = useState<string[]>([]);

  const fetchLogs = useCallback(async () => {
    if (!api) return;
    setLoading(true);
    setError(null);

    try {
      if (service === 'crowdsec') {
        const res = await api.logs.crowdsec(tail);
        setLogs(res.logs || '');
      } else if (service === 'traefik') {
        const [plain, adv] = await Promise.all([api.logs.traefik(tail, logType), api.logs.traefikAdvanced(tail)]);
        setLogs(plain.logs || '');
        setAdvanced(adv);
      } else {
        const generic = await api.logs.service(service, tail);
        setLogs(generic.logs || '');
      }

      const structuredRes = await api.logs.structured(service, tail);
      setStructured(structuredRes);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load logs';
      setError(message);
      setLogs('');
      setAdvanced(null);
      setStructured(null);
    } finally {
      setLoading(false);
    }
  }, [api, logType, service, tail]);

  useMountEffect(() => {
    fetchLogs();
  });

  const stopStream = useCallback(() => {
    wsRef.current?.close();
    wsRef.current = null;
    setIsStreaming(false);
  }, []);

  const startStream = useCallback(() => {
    if (!api || isStreaming) return;

    try {
      const ws = new WebSocket(api.logs.streamUrl(service));
      wsRef.current = ws;
      setStreamLogs([]);

      ws.onopen = () => {
        setIsStreaming(true);
        showActionSuccess('Live log stream connected');
      };

      ws.onmessage = (event) => {
        const line = String(event.data || '');
        setStreamLogs((prev) => [line, ...prev].slice(0, 200));
      };

      ws.onerror = () => {
        showActionError('Log stream error', new Error('WebSocket connection failed'));
      };

      ws.onclose = () => {
        setIsStreaming(false);
      };
    } catch (err) {
      showActionError('Failed to start stream', err);
    }
  }, [api, isStreaming, service]);

  useMountEffect(() => {
    return () => stopStream();
  });

  const structuredText = useMemo(() => {
    if (!structured?.entries) return '';
    return structured.entries
      .map((entry: StructuredLogEntry) => `[${entry.timestamp}] ${entry.level?.toUpperCase() || 'INFO'} ${entry.message}`)
      .join('\n');
  }, [structured]);

  const exportCurrent = () => {
    try {
      const blob = new Blob([logs], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `${service}-logs-${new Date().toISOString()}.txt`;
      anchor.click();
      URL.revokeObjectURL(url);
      showActionSuccess('Logs exported');
    } catch {
      showActionError('Export not supported', new Error('File download is not available in this environment. Copy the logs manually.'));
    }
  };

  return (
    <PullToRefresh onRefresh={fetchLogs}>
      <div className="pb-nav">
        <PageHeader
          title="Logs"
          subtitle="Raw, structured, analytics, and stream"
          action={
            <div className="flex gap-1">
              <Button variant="ghost" size="icon" onClick={fetchLogs} disabled={loading}>
                <RefreshCw className={loading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
              </Button>
              <Button variant="ghost" size="icon" onClick={exportCurrent} disabled={!logs}>
                <Download className="h-4 w-4" />
              </Button>
            </div>
          }
        />

        <div className="px-4 space-y-4">
          <section className="rounded-xl border border-border bg-card p-4 space-y-2">
            <div className="flex items-center gap-2">
              <div className="flex gap-2 flex-1">
                <Button variant={service === 'crowdsec' ? 'default' : 'secondary'} size="sm" onClick={() => setService('crowdsec')}>
                  CrowdSec
                </Button>
                <Button variant={service === 'traefik' ? 'default' : 'secondary'} size="sm" onClick={() => setService('traefik')}>
                  Traefik
                </Button>
              </div>
              <Input placeholder="Lines" value={tail} onChange={(e) => setTail(e.target.value)} className="w-20" />
            </div>
            {service === 'traefik' && (
              <div className="flex gap-2">
                <Button variant={logType === 'access' ? 'default' : 'secondary'} size="sm" onClick={() => setLogType('access')}>
                  Access
                </Button>
                <Button variant={logType === 'error' ? 'default' : 'secondary'} size="sm" onClick={() => setLogType('error')}>
                  Error
                </Button>
              </div>
            )}
          </section>

          <Tabs defaultValue="raw" className="w-full">
            <TabsList className="w-full grid grid-cols-4">
              <TabsTrigger value="raw">Raw</TabsTrigger>
              <TabsTrigger value="structured">Structured</TabsTrigger>
              <TabsTrigger value="advanced">Advanced</TabsTrigger>
              <TabsTrigger value="stream">Stream</TabsTrigger>
            </TabsList>

            <TabsContent value="raw">
              <QueryStateView isLoading={loading} error={error} onRetry={fetchLogs} isEmpty={!logs} emptyTitle="No raw logs" emptyDescription="Refresh to load service logs.">
                <LogPanel content={logs} />
              </QueryStateView>
            </TabsContent>

            <TabsContent value="structured">
              <QueryStateView isLoading={loading} error={error} onRetry={fetchLogs} isEmpty={!structuredText} emptyTitle="No structured logs" emptyDescription="This service may not expose structured log entries.">
                <LogPanel content={structuredText} />
              </QueryStateView>
            </TabsContent>

            <TabsContent value="advanced">
              <LogAdvancedPanel stats={advanced} />
            </TabsContent>

            <TabsContent value="stream" className="space-y-3">
              <section className="rounded-xl border border-border bg-card p-4 space-y-2">
                <div className="flex gap-2">
                  <Button onClick={startStream} disabled={isStreaming}>
                    <Play className="h-4 w-4 mr-1" />Start
                  </Button>
                  <Button variant="secondary" onClick={stopStream} disabled={!isStreaming}>
                    <Square className="h-4 w-4 mr-1" />Stop
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">WebSocket endpoint: `/api/logs/stream/{'{service}'}`</p>
              </section>
              <section className="rounded-xl border border-border bg-card p-4">
                <h3 className="text-sm font-semibold mb-2">Live Stream ({streamLogs.length})</h3>
                <LogPanel content={streamLogs.join('\n')} emptyMessage="Start stream to receive live log lines." />
              </section>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </PullToRefresh>
  );
}

/* ────────────────────── Log Advanced Panel ────────────────────── */

function LogAdvancedPanel({ stats }: { stats: LogStats | null }) {
  if (!stats) {
    return (
      <div className="rounded-xl border border-border bg-card p-4">
        <h3 className="text-sm font-semibold mb-2">Traefik Advanced Analysis</h3>
        <p className="text-sm text-muted-foreground">Advanced stats are available for Traefik service only.</p>
      </div>
    );
  }

  const statusCodeColor = (code: string) => {
    if (code.startsWith('2')) return 'success' as const;
    if (code.startsWith('3')) return 'info' as const;
    if (code.startsWith('4')) return 'warning' as const;
    if (code.startsWith('5')) return 'destructive' as const;
    return 'secondary' as const;
  };

  return (
    <div className="space-y-3">
      {/* Total Lines */}
      <div className="grid grid-cols-2 gap-2">
        <MetricCard label="Total Lines" value={stats.total_lines.toLocaleString()} />
        <MetricCard label="Error Entries" value={stats.error_entries?.length ?? 0} variant={stats.error_entries?.length ? 'warning' : 'default'} />
      </div>

      {/* HTTP Methods */}
      {stats.http_methods && Object.keys(stats.http_methods).length > 0 && (
        <div className="rounded-xl border border-border bg-card p-4 space-y-2">
          <h3 className="text-sm font-semibold">HTTP Methods</h3>
          <div className="flex flex-wrap gap-2">
            {Object.entries(stats.http_methods)
              .sort(([, a], [, b]) => b - a)
              .map(([method, count]) => (
                <Badge key={method} variant="secondary" className="font-mono">
                  {method}: {count.toLocaleString()}
                </Badge>
              ))}
          </div>
        </div>
      )}

      {/* Status Codes */}
      {stats.status_codes && Object.keys(stats.status_codes).length > 0 && (
        <div className="rounded-xl border border-border bg-card p-4 space-y-2">
          <h3 className="text-sm font-semibold">Status Codes</h3>
          <div className="space-y-1.5">
            {Object.entries(stats.status_codes)
              .sort(([, a], [, b]) => b - a)
              .map(([code, count]) => (
                <div key={code} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge variant={statusCodeColor(code)} className="font-mono text-[10px]">{code}</Badge>
                  </div>
                  <span className="text-xs font-mono tabular-nums">{count.toLocaleString()}</span>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Top IPs */}
      {stats.top_ips && stats.top_ips.length > 0 && (
        <div className="rounded-xl border border-border bg-card p-4 space-y-2">
          <h3 className="text-sm font-semibold">Top IPs</h3>
          <div className="space-y-1.5">
            {stats.top_ips.map((entry, i) => (
              <div key={entry.ip} className="flex items-center justify-between py-0.5">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-[10px] text-muted-foreground w-4 text-right">{i + 1}.</span>
                  <span className="text-xs font-mono truncate">{entry.ip}</span>
                </div>
                <span className="text-xs font-mono tabular-nums shrink-0">{entry.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Error Entries */}
      {stats.error_entries && stats.error_entries.length > 0 && (
        <div className="rounded-xl border border-border bg-card p-4 space-y-2">
          <h3 className="text-sm font-semibold">Recent Errors</h3>
          <div className="space-y-2 max-h-[30vh] overflow-y-auto">
            {stats.error_entries.slice(0, 10).map((entry, i) => (
              <div key={i} className="rounded-lg bg-red-500/5 border border-red-500/20 p-2 space-y-0.5">
                <div className="flex items-center gap-2">
                  <StatusDot color="error" />
                  <span className="text-[10px] text-muted-foreground font-mono">{entry.timestamp}</span>
                </div>
                <p className="text-xs truncate">{entry.message}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ────────────────────── Log Panel ────────────────────── */

function LogPanel({ content, emptyMessage = 'No log content.' }: { content: string; emptyMessage?: string }) {
  if (!content) {
    return <p className="text-sm text-muted-foreground">{emptyMessage}</p>;
  }

  return (
    <div className="rounded-xl border border-border bg-card p-4">
      <pre className="text-xs font-mono whitespace-pre-wrap overflow-x-auto max-h-[60vh] overflow-y-auto">{content}</pre>
    </div>
  );
}
