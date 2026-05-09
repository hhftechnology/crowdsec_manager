import { useCallback, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Capacitor } from '@capacitor/core';
import { App as CapApp } from '@capacitor/app';
import { secureStorage } from '@/lib/secureStorage';
import { APP_STORE_URL, PLAY_STORE_URL } from '@/lib/storeLinks';
import { useMountEffect } from '@/hooks/useMountEffect';

const GITHUB_LATEST_RELEASE_URL =
  'https://api.github.com/repos/hhftechnology/crowdsec_manager/releases/latest';
const DISMISSED_STORAGE_KEY = 'csm:manager-update-dismissed';
// 6h: well under GitHub's 60 req/h unauthenticated quota.
const POLL_INTERVAL_MS = 6 * 60 * 60 * 1000;
const STALE_MS = 60 * 60 * 1000;

interface GitHubRelease {
  tag_name: string;
  name: string;
  html_url: string;
  published_at: string;
  prerelease: boolean;
  draft: boolean;
}

export interface ManagerUpdateSummary {
  available: boolean;
  currentVersion: string | null;
  latestVersion: string | null;
  releaseUrl: string | null;
  releaseName: string | null;
  publishedAt: string | null;
  installUrl: string | null;
  dismissed: boolean;
  dismiss: () => void;
  isLoading: boolean;
}

function stripV(s: string): string {
  return s.replace(/^v/i, '').trim();
}

// Returns >0 if a > b, <0 if a < b, 0 if equal.
// Pre-release suffix is treated as lower than the bare release: "1.2.3-rc1" < "1.2.3".
export function compareSemver(a: string, b: string): number {
  const [aMain, aPre] = stripV(a).split('-', 2);
  const [bMain, bPre] = stripV(b).split('-', 2);
  const aParts = aMain.split('.').map((p) => parseInt(p, 10) || 0);
  const bParts = bMain.split('.').map((p) => parseInt(p, 10) || 0);
  const len = Math.max(aParts.length, bParts.length);
  for (let i = 0; i < len; i++) {
    const diff = (aParts[i] ?? 0) - (bParts[i] ?? 0);
    if (diff !== 0) return diff;
  }
  if (aPre && !bPre) return -1;
  if (!aPre && bPre) return 1;
  if (aPre && bPre) return aPre.localeCompare(bPre);
  return 0;
}

async function fetchLatestRelease(): Promise<GitHubRelease | null> {
  const res = await fetch(GITHUB_LATEST_RELEASE_URL, {
    headers: { Accept: 'application/vnd.github+json' },
  });
  if (!res.ok) return null;
  const body = (await res.json()) as GitHubRelease;
  if (body.draft || body.prerelease) return null;
  return body;
}

async function readCurrentVersion(): Promise<string> {
  if (Capacitor.isNativePlatform()) {
    const info = await CapApp.getInfo();
    if (info?.version) return info.version;
  }
  return import.meta.env.VITE_APP_VERSION ?? '0.0.0';
}

function resolveInstallUrl(releaseUrl: string | null): string | null {
  const platform = Capacitor.getPlatform();
  if (platform === 'android' && PLAY_STORE_URL) return PLAY_STORE_URL;
  if (platform === 'ios' && APP_STORE_URL) return APP_STORE_URL;
  return releaseUrl;
}

export function useManagerUpdate(): ManagerUpdateSummary {
  const [currentVersion, setCurrentVersion] = useState<string | null>(null);
  const [dismissedTag, setDismissedTag] = useState<string | null>(null);

  useMountEffect(() => {
    let cancelled = false;
    void (async () => {
      const [version, dismissed] = await Promise.all([
        readCurrentVersion(),
        secureStorage.getItem(DISMISSED_STORAGE_KEY),
      ]);
      if (cancelled) return;
      setCurrentVersion(version);
      setDismissedTag(dismissed);
    })();
    return () => {
      cancelled = true;
    };
  });

  const { data, isLoading } = useQuery({
    queryKey: ['manager-update', 'github-latest'],
    queryFn: fetchLatestRelease,
    refetchInterval: POLL_INTERVAL_MS,
    staleTime: STALE_MS,
    refetchOnWindowFocus: false,
    retry: 1,
  });

  const latestVersion = data ? stripV(data.tag_name) : null;
  const available = !!(
    latestVersion &&
    currentVersion &&
    compareSemver(latestVersion, currentVersion) > 0
  );

  const dismiss = useCallback(() => {
    if (!latestVersion) return;
    void secureStorage.setItem(DISMISSED_STORAGE_KEY, latestVersion);
    setDismissedTag(latestVersion);
  }, [latestVersion]);

  const dismissed = !!latestVersion && dismissedTag === latestVersion;
  const releaseUrl = data?.html_url ?? null;

  return {
    available,
    currentVersion,
    latestVersion,
    releaseUrl,
    releaseName: data?.name ?? null,
    publishedAt: data?.published_at ?? null,
    installUrl: resolveInstallUrl(releaseUrl),
    dismissed,
    dismiss,
    isLoading,
  };
}
