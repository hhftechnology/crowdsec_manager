import { useCallback, useState } from 'react'
import { useQuery } from '@tanstack/react-query'

const GITHUB_LATEST_RELEASE_URL =
  'https://api.github.com/repos/hhftechnology/crowdsec_manager/releases/latest'
const DISMISSED_STORAGE_KEY = 'csm:manager-update-dismissed'
// 6h: well under GitHub's 60 req/h unauthenticated quota even with multiple tabs.
const POLL_INTERVAL_MS = 6 * 60 * 60 * 1000
const STALE_MS = 60 * 60 * 1000

interface GitHubRelease {
  tag_name: string
  name: string
  html_url: string
  published_at: string
  prerelease: boolean
  draft: boolean
}

export interface ManagerUpdateSummary {
  available: boolean
  currentVersion: string
  latestVersion: string | null
  releaseUrl: string | null
  releaseName: string | null
  publishedAt: string | null
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

// stripV trims a leading 'v' or 'V' so "v2.4.0" and "2.4.0" compare equal.
function stripV(s: string): string {
  return s.replace(/^v/i, '').trim()
}

// compareSemver returns >0 if a > b, <0 if a < b, 0 if equal.
// Tolerates non-numeric suffixes (e.g. "2.4.0-rc1") by treating them as
// pre-release: "2.4.0-rc1" < "2.4.0".
export function compareSemver(a: string, b: string): number {
  const [aMain, aPre] = stripV(a).split('-', 2)
  const [bMain, bPre] = stripV(b).split('-', 2)
  const aParts = aMain.split('.').map(p => parseInt(p, 10) || 0)
  const bParts = bMain.split('.').map(p => parseInt(p, 10) || 0)
  const len = Math.max(aParts.length, bParts.length)
  for (let i = 0; i < len; i++) {
    const diff = (aParts[i] ?? 0) - (bParts[i] ?? 0)
    if (diff !== 0) return diff
  }
  if (aPre && !bPre) return -1
  if (!aPre && bPre) return 1
  if (aPre && bPre) return aPre.localeCompare(bPre)
  return 0
}

async function fetchLatestRelease(): Promise<GitHubRelease | null> {
  const res = await fetch(GITHUB_LATEST_RELEASE_URL, {
    headers: { Accept: 'application/vnd.github+json' },
  })
  if (!res.ok) return null
  const body = (await res.json()) as GitHubRelease
  if (body.draft || body.prerelease) return null
  return body
}

export function useManagerUpdate(): ManagerUpdateSummary {
  const currentVersion = import.meta.env.VITE_APP_VERSION ?? '0.0.0'

  const { data, isLoading } = useQuery({
    queryKey: ['manager-update', 'github-latest'],
    queryFn: fetchLatestRelease,
    refetchInterval: POLL_INTERVAL_MS,
    staleTime: STALE_MS,
    refetchOnWindowFocus: false,
    retry: 1,
  })

  const latestVersion = data ? stripV(data.tag_name) : null
  const available = latestVersion ? compareSemver(latestVersion, currentVersion) > 0 : false

  const [dismissedTag, setDismissedTag] = useState<string | null>(() => readDismissed())

  const dismiss = useCallback(() => {
    if (!latestVersion) return
    try {
      window.localStorage.setItem(DISMISSED_STORAGE_KEY, latestVersion)
    } catch {
      // localStorage unavailable; in-memory state still hides the card this session
    }
    setDismissedTag(latestVersion)
  }, [latestVersion])

  const dismissed = !!latestVersion && dismissedTag === latestVersion

  return {
    available,
    currentVersion,
    latestVersion,
    releaseUrl: data?.html_url ?? null,
    releaseName: data?.name ?? null,
    publishedAt: data?.published_at ?? null,
    dismissed,
    dismiss,
    isLoading,
  }
}
