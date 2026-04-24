import { useRef, useCallback, useState } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import type { WebSocketUrlOptions } from '@/lib/api/client';

const MAX_RECONNECT_ATTEMPTS = 3;
const RECONNECT_BASE_DELAY = 1000;

interface UseTerminalOptions {
  getWebSocketUrl: (container: string, options?: WebSocketUrlOptions) => Promise<string>;
  container: string;
  allowPreOpenAuthRefresh?: boolean;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: string) => void;
}

export function useTerminal({
  getWebSocketUrl,
  container,
  allowPreOpenAuthRefresh = false,
  onConnect,
  onDisconnect,
  onError,
}: UseTerminalOptions) {
  const terminalRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const authRefreshAttemptsRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const manualDisconnectRef = useRef(false);
  const [connected, setConnected] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);

  const clearReconnectTimer = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
  }, []);

  const connectWs = useCallback(async (
    term: Terminal,
    fitAddon: FitAddon,
    options?: WebSocketUrlOptions,
  ) => {
    if (!container) return;

    let url = '';
    try {
      url = await getWebSocketUrl(container, options);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unable to prepare WebSocket connection.';
      setConnectionError(message);
      setReconnecting(false);
      onError?.(message);
      return;
    }

    if (!url) {
      setConnectionError('Unable to build WebSocket URL. Check server connection.');
      setReconnecting(false);
      onError?.('Unable to build WebSocket URL');
      return;
    }

    const ws = new WebSocket(url);
    let opened = false;
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    ws.onopen = () => {
      opened = true;
      setConnected(true);
      setReconnecting(false);
      setConnectionError(null);
      reconnectAttemptsRef.current = 0;
      authRefreshAttemptsRef.current = 0;
      onConnect?.();

      const dims = fitAddon.proposeDimensions();
      if (dims) {
        ws.send(JSON.stringify({
          type: 'resize',
          cols: dims.cols,
          rows: dims.rows,
        }));
      }
    };

    ws.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(event.data));
      } else {
        term.write(event.data);
      }
    };

    ws.onclose = () => {
      setConnected(false);

      if (manualDisconnectRef.current) {
        manualDisconnectRef.current = false;
        term.write('\r\n\x1b[33mDisconnected.\x1b[0m\r\n');
        onDisconnect?.();
        return;
      }

      if (!opened && allowPreOpenAuthRefresh && authRefreshAttemptsRef.current < 1) {
        authRefreshAttemptsRef.current += 1;
        setReconnecting(true);
        term.write('\r\n\x1b[33mRefreshing session and retrying...\x1b[0m\r\n');
        void connectWs(term, fitAddon, { forceRefreshAuth: true });
        return;
      }

      if (reconnectAttemptsRef.current < MAX_RECONNECT_ATTEMPTS) {
        const attempt = reconnectAttemptsRef.current + 1;
        const delay = RECONNECT_BASE_DELAY * Math.pow(2, reconnectAttemptsRef.current);
        reconnectAttemptsRef.current = attempt;
        setReconnecting(true);
        term.write('\r\n\x1b[33mConnection lost. Reconnecting (' + attempt + '/' + MAX_RECONNECT_ATTEMPTS + ')...\x1b[0m\r\n');

        reconnectTimerRef.current = setTimeout(() => {
          void connectWs(term, fitAddon);
        }, delay);
      } else {
        term.write('\r\n\x1b[31mSession disconnected. Max reconnection attempts reached.\x1b[0m\r\n');
        setReconnecting(false);
        setConnectionError('Connection lost. Click Reconnect to try again.');
        onDisconnect?.();
      }
    };

    ws.onerror = () => {
      const errorMsg = 'WebSocket connection failed to ' + url.replace(/^wss?:\/\//, '');
      setConnectionError(errorMsg);
      onError?.(errorMsg);
    };
  }, [allowPreOpenAuthRefresh, container, getWebSocketUrl, onConnect, onDisconnect, onError]);

  const connect = useCallback(() => {
    if (!terminalRef.current || !container) return;

    clearReconnectTimer();
    wsRef.current?.close();
    termRef.current?.dispose();

    manualDisconnectRef.current = false;
    reconnectAttemptsRef.current = 0;
    authRefreshAttemptsRef.current = 0;
    setConnectionError(null);

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 12,
      fontFamily: '"JetBrains Mono", Menlo, Monaco, "Courier New", monospace',
      theme: {
        background: '#1a1b26',
        foreground: '#a9b1d6',
        cursor: '#c0caf5',
        selectionBackground: '#33467c',
      },
      allowProposedApi: true,
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalRef.current);
    requestAnimationFrame(() => fitAddon.fit());

    termRef.current = term;
    fitAddonRef.current = fitAddon;

    term.onData((data) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(data);
      }
    });

    void connectWs(term, fitAddon);

    const handleResize = () => {
      fitAddon.fit();
      const dims = fitAddon.proposeDimensions();
      if (dims && wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({
          type: 'resize',
          cols: dims.cols,
          rows: dims.rows,
        }));
      }
    };

    const resizeObserver = new ResizeObserver(handleResize);
    resizeObserver.observe(terminalRef.current);

    return () => {
      resizeObserver.disconnect();
      clearReconnectTimer();
      wsRef.current?.close();
      term.dispose();
      termRef.current = null;
      wsRef.current = null;
      fitAddonRef.current = null;
      setConnected(false);
      setReconnecting(false);
    };
  }, [clearReconnectTimer, connectWs, container]);

  const disconnect = useCallback(() => {
    manualDisconnectRef.current = true;
    clearReconnectTimer();
    wsRef.current?.close();
    termRef.current?.dispose();
    termRef.current = null;
    wsRef.current = null;
    setConnected(false);
    setReconnecting(false);
  }, [clearReconnectTimer]);

  const reconnect = useCallback(() => {
    reconnectAttemptsRef.current = 0;
    authRefreshAttemptsRef.current = 0;
    setConnectionError(null);
    connect();
  }, [connect]);

  useMountEffect(() => {
    return () => {
      clearReconnectTimer();
      wsRef.current?.close();
      termRef.current?.dispose();
    };
  });

  return {
    terminalRef,
    connected,
    reconnecting,
    connectionError,
    connect,
    disconnect,
    reconnect,
  };
}
