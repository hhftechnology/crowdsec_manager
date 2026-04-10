import { ApiError } from '@/lib/api';

export type AppErrorKind = 'offline' | 'unreachable' | 'timeout' | 'server' | 'unknown';

export interface AppErrorState {
  title: string;
  message: string;
  kind: AppErrorKind;
}

interface NormalizeAppErrorOptions {
  baseUrl?: string;
  fallbackMessage?: string;
}

const REQUEST_FAILED_ERROR: AppErrorState = {
  title: 'Request failed',
  message: 'Something went wrong while loading data. Try again.',
  kind: 'unknown',
};

export function normalizeAppError(
  error: unknown,
  options: NormalizeAppErrorOptions = {},
): AppErrorState {
  const { baseUrl, fallbackMessage = REQUEST_FAILED_ERROR.message } = options;

  if (isOffline()) {
    return {
      title: 'You are offline',
      message: 'Reconnect your device to the internet or local network, then try again.',
      kind: 'offline',
    };
  }

  if (isAbortError(error)) {
    return {
      title: 'Request timed out',
      message: 'The request took too long to complete. Try again in a moment.',
      kind: 'timeout',
    };
  }

  if (error instanceof ApiError) {
    return {
      title: error.status >= 500 ? 'Server error' : 'Request failed',
      message: error.message || fallbackMessage,
      kind: 'server',
    };
  }

  const message = extractErrorMessage(error);
  if (message === 'Failed to fetch' || message === 'Load failed' || message === 'Network request failed') {
    return {
      title: 'API unreachable',
      message: baseUrl
        ? `Could not reach ${baseUrl}. Check server status, URL, and network path.`
        : 'Could not reach the API. Check server status, URL, and network path.',
      kind: 'unreachable',
    };
  }

  if (message) {
    return {
      title: REQUEST_FAILED_ERROR.title,
      message,
      kind: 'unknown',
    };
  }

  return {
    ...REQUEST_FAILED_ERROR,
    message: fallbackMessage,
  };
}

function extractErrorMessage(error: unknown): string | null {
  if (typeof error === 'string' && error.trim()) {
    return error;
  }

  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }

  return null;
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException
    ? error.name === 'AbortError'
    : error instanceof Error && error.name === 'AbortError';
}

function isOffline(): boolean {
  return typeof navigator !== 'undefined' && 'onLine' in navigator && navigator.onLine === false;
}
