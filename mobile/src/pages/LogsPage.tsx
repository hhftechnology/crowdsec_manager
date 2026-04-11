import { useCallback, useMemo, useRef, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { RefreshCw, Play, Square, Download } from 'lucide-react';
import { PageHeader } from '@/components/PageHeader';
import { useApi } from '@/contexts/ApiContext';
import { PullToRefresh } from '@/components/PullToRefresh';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { QueryStateView } from '@/components/QueryStateView';
import { showActionError, showActionSuccess } from '@/lib/actionToast';
import type { StructuredLogEntry, StructuredLogsResponse } from '@/lib/api';

export default function LogsPage() {
  const { api } = useApi();
  const wsRef = useRef<WebSocket | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [tail, setTail] = useState('200');
  const [logs, setLogs] = useState<string>('');
  const [structured, setStructured] = useState<StructuredLogsResponse | null>(null);

  const [isStreaming, setIsStreaming] = useState(false);
  const [streamLogs, setStreamLogs] = useState<string[]>([]);

  const fetchLogs = useCallback(async () => {
    if (!api) return;
    setLoading(true);
    setError(null);

    try {
      const [plain, structuredRes] = await Promise.all([
        api.logs.crowdsec(tail),
        api.logs.structured('crowdsec', tail),
      ]);
      setLogs(plain.logs || '');
      setStructured(structuredRes);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load logs';
      setError(message);
      setLogs('');
      setStructured(null);
    } finally {
      setLoading(false);
    }
  }, [api, tail]);

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
      const ws = new WebSocket(api.logs.streamUrl('crowdsec'));
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
  }, [api, isStreaming]);

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
      anchor.download = `crowdsec-logs-${new Date().toISOString()}.txt`;
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
          subtitle="CrowdSec raw, structured, and stream"
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
              <Input placeholder="Lines" value={tail} onChange={(e) => setTail(e.target.value)} className="w-20" />
            </div>
          </section>

          <Tabs defaultValue="raw" className="w-full">
            <TabsList className="w-full grid grid-cols-3">
              <TabsTrigger value="raw">Raw</TabsTrigger>
              <TabsTrigger value="structured">Structured</TabsTrigger>
              <TabsTrigger value="stream">Stream</TabsTrigger>
            </TabsList>

            <TabsContent value="raw">
              <QueryStateView isLoading={loading} error={error} onRetry={fetchLogs} isEmpty={!logs} emptyTitle="No raw logs" emptyDescription="Refresh to load CrowdSec logs.">
                <LogPanel content={logs} />
              </QueryStateView>
            </TabsContent>

            <TabsContent value="structured">
              <QueryStateView isLoading={loading} error={error} onRetry={fetchLogs} isEmpty={!structuredText} emptyTitle="No structured logs" emptyDescription="CrowdSec did not return structured log entries.">
                <LogPanel content={structuredText} />
              </QueryStateView>
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
                <p className="text-xs text-muted-foreground">WebSocket endpoint: `/api/logs/stream/crowdsec`</p>
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
