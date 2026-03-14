import { useState, useEffect, useRef, useCallback } from 'react'

interface SSEEvent {
  type: string
  id?: string
  payload?: Record<string, unknown>
}

interface UseSSEResult {
  lastEvent: SSEEvent | null
  isConnected: boolean
}

export function useSSE(url: string): UseSSEResult {
  const [lastEvent, setLastEvent] = useState<SSEEvent | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const retryDelay = useRef(1000)
  const eventSourceRef = useRef<EventSource | null>(null)

  const connect = useCallback(() => {
    const es = new EventSource(url)
    eventSourceRef.current = es

    es.onopen = () => {
      setIsConnected(true)
      retryDelay.current = 1000
    }

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as SSEEvent
        setLastEvent(data)
      } catch {
        // Ignore malformed events
      }
    }

    es.onerror = () => {
      setIsConnected(false)
      es.close()

      // Exponential backoff reconnect (max 30s)
      const delay = retryDelay.current
      retryDelay.current = Math.min(delay * 2, 30000)

      setTimeout(connect, delay)
    }
  }, [url])

  useEffect(() => {
    connect()

    return () => {
      eventSourceRef.current?.close()
    }
  }, [connect])

  return { lastEvent, isConnected }
}
