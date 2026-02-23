import { useEffect, useRef, useState, useCallback } from 'react'
import { eventsAPI } from '@/lib/api'

interface RealtimeEvent {
  id: string
  type: string
  timestamp: string
  host_id?: string
  payload: unknown
}

interface UseRealtimeEventsOptions {
  subjects?: string[]
  onEvent?: (event: RealtimeEvent) => void
  autoConnect?: boolean
}

export function useRealtimeEvents({
  subjects = [],
  onEvent,
  autoConnect = true,
}: UseRealtimeEventsOptions = {}) {
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>()
  const [connected, setConnected] = useState(false)
  const [events, setEvents] = useState<RealtimeEvent[]>([])

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const url = eventsAPI.getWebSocketUrl()
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      // Subscribe to requested subjects
      if (subjects.length > 0) {
        ws.send(JSON.stringify({ subscribe: subjects }))
      }
    }

    ws.onmessage = (evt) => {
      try {
        const event: RealtimeEvent = JSON.parse(evt.data)
        setEvents((prev) => [...prev.slice(-99), event]) // Keep last 100
        onEvent?.(event)
      } catch {
        // Ignore non-JSON messages
      }
    }

    ws.onclose = () => {
      setConnected(false)
      // Auto-reconnect after 3 seconds
      reconnectTimer.current = setTimeout(connect, 3000)
    }

    ws.onerror = () => {
      ws.close()
    }
  }, [subjects, onEvent])

  const disconnect = useCallback(() => {
    clearTimeout(reconnectTimer.current)
    wsRef.current?.close()
    wsRef.current = null
    setConnected(false)
  }, [])

  useEffect(() => {
    if (autoConnect) {
      connect()
    }
    return () => {
      clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [autoConnect, connect])

  return {
    connected,
    events,
    connect,
    disconnect,
    clearEvents: () => setEvents([]),
  }
}
