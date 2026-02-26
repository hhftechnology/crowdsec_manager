import { useEffect, useRef, useCallback, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { terminalAPI } from '@/lib/api'

interface UseTerminalOptions {
  container: string
  onConnect?: () => void
  onDisconnect?: () => void
  onError?: (error: string) => void
}

export function useTerminal({ container, onConnect, onDisconnect, onError }: UseTerminalOptions) {
  const terminalRef = useRef<HTMLDivElement | null>(null)
  const termRef = useRef<Terminal | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const fitAddonRef = useRef<FitAddon | null>(null)
  const [connected, setConnected] = useState(false)

  const connect = useCallback(() => {
    if (!terminalRef.current || !container) return

    // Create terminal
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
      theme: {
        background: '#1a1b26',
        foreground: '#a9b1d6',
        cursor: '#c0caf5',
        selectionBackground: '#33467c',
      },
      allowProposedApi: true,
    })

    const fitAddon = new FitAddon()
    term.loadAddon(fitAddon)
    term.open(terminalRef.current)
    fitAddon.fit()

    termRef.current = term
    fitAddonRef.current = fitAddon

    // Connect WebSocket
    const url = terminalAPI.getWebSocketUrl(container)
    const ws = new WebSocket(url)
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      onConnect?.()

      // Send initial resize
      const dims = fitAddon.proposeDimensions()
      if (dims) {
        ws.send(JSON.stringify({
          type: 'resize',
          cols: dims.cols,
          rows: dims.rows,
        }))
      }
    }

    ws.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(event.data))
      } else {
        term.write(event.data)
      }
    }

    ws.onclose = () => {
      setConnected(false)
      term.write('\r\n\x1b[31mSession disconnected.\x1b[0m\r\n')
      onDisconnect?.()
    }

    ws.onerror = () => {
      onError?.('WebSocket connection failed')
    }

    // Forward terminal input to WebSocket
    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data)
      }
    })

    // Handle resize
    const handleResize = () => {
      fitAddon.fit()
      const dims = fitAddon.proposeDimensions()
      if (dims && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'resize',
          cols: dims.cols,
          rows: dims.rows,
        }))
      }
    }

    const resizeObserver = new ResizeObserver(handleResize)
    resizeObserver.observe(terminalRef.current)

    return () => {
      resizeObserver.disconnect()
      ws.close()
      term.dispose()
      termRef.current = null
      wsRef.current = null
      fitAddonRef.current = null
      setConnected(false)
    }
  }, [container, onConnect, onDisconnect, onError])

  const disconnect = useCallback(() => {
    wsRef.current?.close()
    termRef.current?.dispose()
    termRef.current = null
    wsRef.current = null
    setConnected(false)
  }, [])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      wsRef.current?.close()
      termRef.current?.dispose()
    }
  }, [])

  return {
    terminalRef,
    connected,
    connect,
    disconnect,
  }
}
