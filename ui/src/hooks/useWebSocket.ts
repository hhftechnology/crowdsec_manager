import { useCallback, useEffect, useRef, useState } from "react";
import type { LogEntry } from "@/types/models";

const MAX_MESSAGES = 500;
const MAX_RECONNECT_DELAY = 30_000;

export function useWebSocket(url: string, enabled = true) {
  const [messages, setMessages] = useState<LogEntry[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const enabledRef = useRef(enabled);
  enabledRef.current = enabled;

  const disconnect = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setIsConnected(false);
  }, []);

  const connect = useCallback(() => {
    if (!enabledRef.current) return;

    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.addEventListener("open", () => {
        setIsConnected(true);
        reconnectAttemptRef.current = 0;
      });

      ws.addEventListener("message", (event: MessageEvent) => {
        try {
          const entry = JSON.parse(String(event.data)) as LogEntry;
          setMessages((prev) => {
            const next = [...prev, entry];
            return next.length > MAX_MESSAGES ? next.slice(-MAX_MESSAGES) : next;
          });
        } catch {
          // ignore malformed messages
        }
      });

      ws.addEventListener("close", () => {
        setIsConnected(false);
        wsRef.current = null;

        if (enabledRef.current) {
          const delay = Math.min(
            1000 * 2 ** reconnectAttemptRef.current,
            MAX_RECONNECT_DELAY,
          );
          reconnectAttemptRef.current += 1;
          reconnectTimerRef.current = setTimeout(connect, delay);
        }
      });

      ws.addEventListener("error", () => {
        ws.close();
      });
    } catch {
      // connection failed, will retry via close handler
    }
  }, [url]);

  useEffect(() => {
    if (enabled) {
      connect();
    } else {
      disconnect();
    }
    return disconnect;
  }, [enabled, connect, disconnect]);

  const clearMessages = useCallback(() => {
    setMessages([]);
  }, []);

  return { messages, isConnected, disconnect, clearMessages };
}
