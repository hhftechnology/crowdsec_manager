import { useCallback, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import api from '@/lib/api'
import type { ServiceUpdateStatus } from '@/lib/api/types'

const DISMISSED_STORAGE_KEY = 'csm:update-dismissed'
const POLL_INTERVAL_MS = 6 * 60 * 60 * 1000
const STALE_MS = 60 * 60 * 1000

export interface UpdateAvailableSummary {
  available: boolean
  services: Array<{ name: string; status: ServiceUpdateStatus }>
  // signature changes when the set of available updates changes; used to key dismissal
  signature: string
  dismissed: boolean
  dismiss: () => void
  isLoading: boolean
}

function readDismissed(): string | null {
  try {
    return window.localStorage.getItem(DISMISSED_STORAGE_KEY)
  } catch {
    return null
  }
}

function buildSignature(services: Array<{ name: string; status: ServiceUpdateStatus }>): string {
  return services
    .map(s => `${s.name}:${s.status.current_tag}`)
    .sort()
    .join('|')
}

export function useUpdateAvailable(): UpdateAvailableSummary {
  const { data, isLoading } = useQuery({
    queryKey: ['update-check', 'sidebar'],
    queryFn: async () => (await api.update.checkForUpdates()).data.data,
    refetchInterval: POLL_INTERVAL_MS,
    staleTime: STALE_MS,
    refetchOnWindowFocus: false,
  })

  const services = data
    ? Object.entries(data)
        .filter(([, status]) => status?.update_available)
        .map(([name, status]) => ({ name, status }))
    : []

  const signature = buildSignature(services)

  const [dismissedSignature, setDismissedSignature] = useState<string | null>(() => readDismissed())

  const dismiss = useCallback(() => {
    try {
      window.localStorage.setItem(DISMISSED_STORAGE_KEY, signature)
    } catch {
      // localStorage unavailable; in-memory state still hides the card this session
    }
    setDismissedSignature(signature)
  }, [signature])

  const dismissed = signature !== '' && dismissedSignature === signature

  return {
    available: services.length > 0,
    services,
    signature,
    dismissed,
    dismiss,
    isLoading,
  }
}
