import { useEffect, useRef } from 'react'
import { toast } from 'sonner'
import { useSSE } from './useSSE'

export function useConfigEvents() {
  const { lastEvent } = useSSE('/api/events/sse')
  const processedRef = useRef<string | null>(null)

  useEffect(() => {
    if (!lastEvent) return

    // Deduplicate by creating a simple event key
    const eventKey = `${lastEvent.type}-${lastEvent.payload?.config_type}-${Date.now()}`
    if (processedRef.current === eventKey) return
    processedRef.current = eventKey

    const configType = lastEvent.payload?.config_type ?? 'unknown'
    const filePath = lastEvent.payload?.file_path ?? ''

    switch (lastEvent.type) {
      case 'config_drift':
        toast.warning(`Config drift detected: ${configType}`, {
          description: `${filePath} has changed since last snapshot`,
          duration: 10000,
        })
        break

      case 'config_missing':
        toast.error(`Config missing: ${configType}`, {
          description: `${filePath} is not accessible in container`,
          duration: 10000,
        })
        break

      case 'config_restored':
        toast.success(`Config restored: ${configType}`, {
          description: `${filePath} restored from snapshot`,
          duration: 5000,
        })
        break
    }
  }, [lastEvent])
}
