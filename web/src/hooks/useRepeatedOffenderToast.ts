import { useEffect, useRef } from 'react'
import { toast } from 'sonner'
import type { RepeatedOffender } from '@/lib/api'
import type { useSSE } from './useSSE'

type SSEEvent = ReturnType<typeof useSSE>['lastEvent']

export function useRepeatedOffenderToast(lastEvent: SSEEvent): void {
  const seenRealtimeEventsRef = useRef<Set<string>>(new Set())

  useEffect(() => {
    if (!lastEvent || lastEvent.type !== 'crowdsec.repeated_offender') {
      return
    }

    const eventId = lastEvent.id ?? JSON.stringify(lastEvent.payload ?? {})
    if (seenRealtimeEventsRef.current.has(eventId)) {
      return
    }
    seenRealtimeEventsRef.current.add(eventId)

    const payload = (lastEvent.payload ?? {}) as Partial<RepeatedOffender>
    const value = payload.value ?? 'unknown'
    const count = payload.hit_count ?? 0
    toast.warning(`Repeated offender detected: ${value} (${count} hits in 30d)`)
  }, [lastEvent])
}
