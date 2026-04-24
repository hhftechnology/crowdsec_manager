import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import {
  buildConnectionCandidates,
  createDefaultConnectionProfileDraft,
  finalizeConnectionProfile,
  isExplicitHttpUrl,
  normalizeConnectionProfileDraft,
  parseStoredConnectionProfile,
  serializeConnectionProfile,
  parsePangolinAccessToken,
  type ConnectionProfile,
  type ConnectionProfileDraft,
  type ConnectionMode,
} from '@/lib/connection';
import { createApi, ApiError, type ApiService } from '@/lib/api';
import { normalizeAppError } from '@/lib/errors';

interface ApiContextType {
  connectionProfile: ConnectionProfile | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  login: (profile: ConnectionProfileDraft) => Promise<boolean>;
  logout: () => void;
  api: ApiService | null;
}

const CONNECTION_PROFILE_KEY = 'csm_connection_profile';
const LEGACY_BASE_URL_KEY = 'csm_base_url';
const LEGACY_INSECURE_KEY = 'csm_allow_insecure';

const ApiContext = createContext<ApiContextType | null>(null);

function readInitialConnectionProfile(): ConnectionProfile | null {
  const stored = parseStoredConnectionProfile(localStorage.getItem(CONNECTION_PROFILE_KEY));
  if (stored) return stored;

  const legacyBaseUrl = localStorage.getItem(LEGACY_BASE_URL_KEY);
  if (!legacyBaseUrl) return null;

  return normalizeConnectionProfileDraft({
    ...createDefaultConnectionProfileDraft(),
    baseUrl: legacyBaseUrl,
    allowInsecure: localStorage.getItem(LEGACY_INSECURE_KEY) === 'true',
  });
}

function getValidationError(draft: ConnectionProfileDraft): string | null {
  if (!draft.baseUrl) {
    return 'Server URL is required.';
  }

  if (!draft.allowInsecure && isExplicitHttpUrl(draft.baseUrl)) {
    return 'HTTPS is required in secure mode. Enable insecure mode only for trusted LAN servers.';
  }

  if (draft.mode === 'proxy-basic' && (!draft.proxyUsername || !draft.proxyPassword)) {
    return 'Proxy username and password are required.';
  }

  if (draft.mode === 'pangolin' && !parsePangolinAccessToken(draft.pangolinToken)) {
    return 'Pangolin access token must use the format tokenId.tokenSecret.';
  }

  return null;
}

function getConnectionErrorMessage(error: unknown, mode: ConnectionMode, baseUrl: string, allowInsecure: boolean, inputUrl: string): string {
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

  if (!allowInsecure && normalizedError.kind === 'unreachable' && isExplicitHttpUrl(inputUrl)) {
    return 'Could not reach the server. If using HTTP or a LAN address, enable Insecure/LAN Mode.';
  }

  return normalizedError.message;
}

export const useApi = () => {
  const ctx = useContext(ApiContext);
  if (!ctx) throw new Error('useApi must be used within ApiProvider');
  return ctx;
};

export const ApiProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [connectionProfile, setConnectionProfile] = useState<ConnectionProfile | null>(readInitialConnectionProfile);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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

    const candidates = buildConnectionCandidates(draft.baseUrl, draft.allowInsecure);
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
          localStorage.setItem(CONNECTION_PROFILE_KEY, serializeConnectionProfile(candidateProfile));
          localStorage.removeItem(LEGACY_BASE_URL_KEY);
          localStorage.removeItem(LEGACY_INSECURE_KEY);
          return true;
        } catch (candidateError) {
          lastError = candidateError;
        }
      }

      setError(getConnectionErrorMessage(lastError, draft.mode, lastBaseUrl, draft.allowInsecure, draft.baseUrl));
      return false;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(CONNECTION_PROFILE_KEY);
    localStorage.removeItem(LEGACY_BASE_URL_KEY);
    localStorage.removeItem(LEGACY_INSECURE_KEY);
    setConnectionProfile(null);
    setError(null);
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
