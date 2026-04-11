import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { createApi, type ApiService } from '@/lib/api';
import { normalizeAppError } from '@/lib/errors';

interface ApiContextType {
  baseUrl: string;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  allowInsecure: boolean;
  setAllowInsecure: (enabled: boolean) => void;
  login: (url: string) => Promise<boolean>;
  logout: () => void;
  api: ApiService | null;
}

const BASE_URL_KEY = 'csm_base_url';
const INSECURE_KEY = 'csm_allow_insecure';

const ApiContext = createContext<ApiContextType | null>(null);

function normalizeUrl(url: string): string {
  return url.trim().replace(/\/+$/, '');
}

function getInitialAllowInsecure(): boolean {
  return localStorage.getItem(INSECURE_KEY) === 'true';
}

export const useApi = () => {
  const ctx = useContext(ApiContext);
  if (!ctx) throw new Error('useApi must be used within ApiProvider');
  return ctx;
};

export const ApiProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [baseUrl, setBaseUrl] = useState(() => localStorage.getItem(BASE_URL_KEY) || '');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [allowInsecure, setAllowInsecureState] = useState(getInitialAllowInsecure);

  const api = useMemo(() => {
    if (!baseUrl) return null;
    return createApi(baseUrl);
  }, [baseUrl]);

  const setAllowInsecure = useCallback((enabled: boolean) => {
    setAllowInsecureState(enabled);
    localStorage.setItem(INSECURE_KEY, String(enabled));
  }, []);

  const login = useCallback(
    async (url: string) => {
      setIsLoading(true);
      setError(null);

      const cleanUrl = normalizeUrl(url);
      if (!cleanUrl) {
        setError('Server URL is required.');
        setIsLoading(false);
        return false;
      }

      if (!allowInsecure && cleanUrl.startsWith('http://')) {
        setError('HTTPS is required in secure mode. Enable insecure mode only for trusted LAN servers.');
        setIsLoading(false);
        return false;
      }

      try {
        const res = await fetch(`${cleanUrl}/api/health/stack`);
        if (!res.ok) {
          throw new Error(`Could not reach API (${res.status} ${res.statusText})`);
        }

        setBaseUrl(cleanUrl);
        localStorage.setItem(BASE_URL_KEY, cleanUrl);
        setIsLoading(false);
        return true;
      } catch (err) {
        const normalizedError = normalizeAppError(err, {
          baseUrl: cleanUrl,
          fallbackMessage: 'Could not connect to the server.',
        });

        let message = normalizedError.message;
        if (!allowInsecure && normalizedError.kind === 'unreachable' && cleanUrl.startsWith('http://')) {
          message = 'Could not reach the server. If using HTTP or a LAN address, enable Insecure/LAN Mode.';
        }
        setError(message);
        setIsLoading(false);
        return false;
      }
    },
    [allowInsecure],
  );

  const logout = useCallback(() => {
    localStorage.removeItem(BASE_URL_KEY);
    setBaseUrl('');
    setError(null);
  }, []);

  const value = useMemo<ApiContextType>(
    () => ({
      baseUrl,
      isAuthenticated: Boolean(baseUrl),
      isLoading,
      error,
      allowInsecure,
      setAllowInsecure,
      login,
      logout,
      api,
    }),
    [allowInsecure, api, baseUrl, error, isLoading, login, logout, setAllowInsecure],
  );

  return <ApiContext.Provider value={value}>{children}</ApiContext.Provider>;
};
