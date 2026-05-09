import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import {
  buildConnectionCandidates,
  canAutoRestoreConnectionProfile,
  createDefaultConnectionProfileDraft,
  finalizeConnectionProfile,
  isExplicitHttpUrl,
  normalizeConnectionProfileDraft,
  parsePangolinAccessToken,
  parseStoredConnectionProfile,
  serializeConnectionProfile,
  type ConnectionMode,
  type ConnectionProfile,
  type ConnectionProfileDraft,
} from '@/lib/connection';
import { createApi, ApiError, type ApiService } from '@/lib/api';
import { queryClient } from '@/lib/api/queryClient';
import { normalizeAppError } from '@/lib/errors';
import { secureStorage } from '@/lib/secureStorage';
import { useMountEffect } from '@/hooks/useMountEffect';

interface ApiContextType {
  connectionProfile: ConnectionProfile | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  login: (profile: ConnectionProfileDraft) => Promise<boolean>;
  logout: () => Promise<void>;
  api: ApiService | null;
}

const CONNECTION_PROFILE_KEY = 'csm_connection_profile';
const LEGACY_BASE_URL_KEY = 'csm_base_url';
const LEGACY_INSECURE_KEY = 'csm_allow_insecure';

const ApiContext = createContext<ApiContextType | null>(null);

async function loadInitialConnectionProfile(): Promise<ConnectionProfile | null> {
  const stored = parseStoredConnectionProfile(
    await secureStorage.getItem(CONNECTION_PROFILE_KEY),
  );
  if (stored && canAutoRestoreConnectionProfile(stored)) return stored;

  const legacyBaseUrl = await secureStorage.getItem(LEGACY_BASE_URL_KEY);
  if (!legacyBaseUrl) return null;

  const legacyInsecure = await secureStorage.getItem(LEGACY_INSECURE_KEY);
  return normalizeConnectionProfileDraft({
    ...createDefaultConnectionProfileDraft(),
    baseUrl: legacyBaseUrl,
    allowInsecure: legacyInsecure === 'true',
  });
}

function getValidationError(draft: ConnectionProfileDraft): string | null {
  if (!draft.baseUrl) {
    return 'Server URL is required.';
  }

  if (!draft.allowInsecure && isExplicitHttpUrl(draft.baseUrl)) {
    return 'HTTPS is required in secure mode. Enable insecure mode only for trusted LAN servers.';
  }

  if (
    draft.mode === 'proxy-basic' &&
    (!draft.proxyUsername || !draft.proxyPassword)
  ) {
    return 'Proxy username and password are required.';
  }

  if (
    draft.mode === 'pangolin' &&
    !parsePangolinAccessToken(draft.pangolinToken)
  ) {
    return 'Pangolin access token must use the format tokenId.tokenSecret.';
  }

  return null;
}

function getConnectionErrorMessage(
  error: unknown,
  mode: ConnectionMode,
  baseUrl: string,
  allowInsecure: boolean,
  inputUrl: string,
): string {
  if (error instanceof ApiError && error.status === 401) {
    if (mode === 'proxy-basic') {
      return 'Proxy authentication failed. Check the proxy username and password.';
    }

    if (mode === 'pangolin') {
      return 'Pangolin authentication failed. Check the URL and access token.';
    }
  }

  const normalizedError = normalizeAppError(error, {
    baseUrl,
    fallbackMessage: 'Could not connect to the server.',
  });

  if (
    !allowInsecure &&
    normalizedError.kind === 'unreachable' &&
    isExplicitHttpUrl(inputUrl)
  ) {
    return 'Could not reach the server. If using HTTP or a LAN address, enable Insecure/LAN Mode.';
  }

  return normalizedError.message;
}

export const useApi = () => {
  const ctx = useContext(ApiContext);
  if (!ctx) throw new Error('useApi must be used within ApiProvider');
  return ctx;
};

export const ApiProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [connectionProfile, setConnectionProfile] =
    useState<ConnectionProfile | null>(null);
  // Starts true so App.tsx renders the loader instead of flashing the login
  // screen while we read the persisted profile from native storage.
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useMountEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const profile = await loadInitialConnectionProfile();
        if (cancelled) return;
        if (profile) {
          setConnectionProfile(profile);
          // Migrate legacy keys: re-persist under the new key, drop the old ones.
          await secureStorage.setItem(
            CONNECTION_PROFILE_KEY,
            serializeConnectionProfile(profile),
          );
          await secureStorage.removeItem(LEGACY_BASE_URL_KEY);
          await secureStorage.removeItem(LEGACY_INSECURE_KEY);
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  });

  const api = useMemo(() => {
    if (!connectionProfile) return null;
    return createApi(connectionProfile);
  }, [connectionProfile]);

  const login = useCallback(async (profileDraft: ConnectionProfileDraft) => {
    setIsLoading(true);
    setError(null);

    const draft = normalizeConnectionProfileDraft(profileDraft);
    const validationError = getValidationError(draft);
    if (validationError) {
      setError(validationError);
      setIsLoading(false);
      return false;
    }

    const candidates = buildConnectionCandidates(
      draft.baseUrl,
      draft.allowInsecure,
    );
    if (candidates.length === 0) {
      setError('Enter a valid server URL, domain, or IP address.');
      setIsLoading(false);
      return false;
    }

    let lastError: unknown = null;
    let lastBaseUrl = draft.baseUrl;

    try {
      for (const candidate of candidates) {
        const candidateProfile = finalizeConnectionProfile(draft, candidate);
        lastBaseUrl = candidateProfile.baseUrl;

        try {
          const nextApi = createApi(candidateProfile);
          await nextApi.client.verifyConnection();

          setConnectionProfile(candidateProfile);
          await secureStorage.setItem(
            CONNECTION_PROFILE_KEY,
            serializeConnectionProfile(candidateProfile),
          );
          await secureStorage.removeItem(LEGACY_BASE_URL_KEY);
          await secureStorage.removeItem(LEGACY_INSECURE_KEY);
          queryClient.clear();
          return true;
        } catch (candidateError) {
          lastError = candidateError;
        }
      }

      setError(
        getConnectionErrorMessage(
          lastError,
          draft.mode,
          lastBaseUrl,
          draft.allowInsecure,
          draft.baseUrl,
        ),
      );
      return false;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    await secureStorage.removeItem(CONNECTION_PROFILE_KEY);
    await secureStorage.removeItem(LEGACY_BASE_URL_KEY);
    await secureStorage.removeItem(LEGACY_INSECURE_KEY);
    setConnectionProfile(null);
    setError(null);
    queryClient.clear();
  }, []);

  const value = useMemo<ApiContextType>(
    () => ({
      connectionProfile,
      isAuthenticated: Boolean(connectionProfile),
      isLoading,
      error,
      login,
      logout,
      api,
    }),
    [api, connectionProfile, error, isLoading, login, logout],
  );

  return <ApiContext.Provider value={value}>{children}</ApiContext.Provider>;
};
