import type { ApiEnvelope, ApiResult } from './types';

export class ApiError extends Error {
  status: number;
  details?: unknown;

  constructor(message: string, status: number, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

export interface RequestOptions {
  params?: Record<string, string | number | boolean | undefined | null>;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  responseType?: 'json' | 'text';
}

export interface MutationOptions extends RequestOptions {
  body?: unknown;
}

function buildQuery(params?: RequestOptions['params']): string {
  if (!params) return '';
  const q = new URLSearchParams();

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    q.set(key, String(value));
  }

  const out = q.toString();
  return out ? `?${out}` : '';
}

function normalizePath(path: string): string {
  return path.startsWith('/') ? path : `/${path}`;
}

function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, '');
}

function hasEnvelope(value: unknown): value is ApiEnvelope<unknown> {
  return Boolean(
    value &&
      typeof value === 'object' &&
      'success' in value &&
      typeof (value as { success: unknown }).success === 'boolean',
  );
}

export class ApiClient {
  private readonly baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
  }

  async get<T>(path: string, options?: RequestOptions): Promise<ApiResult<T>> {
    return this.request<T>('GET', path, options);
  }

  async post<T>(path: string, options?: MutationOptions): Promise<ApiResult<T>> {
    return this.request<T>('POST', path, options);
  }

  async put<T>(path: string, options?: MutationOptions): Promise<ApiResult<T>> {
    return this.request<T>('PUT', path, options);
  }

  async delete<T>(path: string, options?: MutationOptions): Promise<ApiResult<T>> {
    return this.request<T>('DELETE', path, options);
  }

  getWebSocketUrl(path: string, params?: RequestOptions['params']): string {
    const url = `${this.baseUrl}${normalizePath(path)}${buildQuery(params)}`;
    const parsed = new URL(url);
    parsed.protocol = parsed.protocol === 'https:' ? 'wss:' : 'ws:';
    return parsed.toString();
  }

  private async request<T>(method: string, path: string, options?: MutationOptions): Promise<ApiResult<T>> {
    const requestUrl = `${this.baseUrl}${normalizePath(path)}${buildQuery(options?.params)}`;

    const headers: Record<string, string> = {
      ...(options?.headers ?? {}),
    };

    const init: RequestInit = {
      method,
      headers,
      signal: options?.signal,
    };

    if (options?.body !== undefined) {
      if (options.body instanceof FormData) {
        init.body = options.body;
      } else {
        headers['Content-Type'] = 'application/json';
        init.body = JSON.stringify(options.body);
      }
    }

    const response = await fetch(requestUrl, init);
    const contentType = response.headers.get('content-type') || '';
    const shouldTreatAsText = options?.responseType === 'text' || contentType.includes('text/plain');

    let payload: unknown;
    if (shouldTreatAsText) {
      payload = await response.text();
    } else {
      const raw = await response.text();
      payload = raw ? safeJsonParse(raw) : undefined;
    }

    if (!response.ok) {
      const message = extractErrorMessage(payload) || `${response.status} ${response.statusText}`;
      throw new ApiError(message, response.status, payload);
    }

    if (hasEnvelope(payload)) {
      if (!payload.success) {
        throw new ApiError(payload.error || payload.message || 'Request failed', response.status, payload);
      }
      return {
        data: (payload.data as T) ?? (null as T),
        message: payload.message,
      };
    }

    return {
      data: (payload as T) ?? (null as T),
    };
  }
}

function safeJsonParse(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function extractErrorMessage(payload: unknown): string | undefined {
  if (!payload) return undefined;
  if (typeof payload === 'string') return payload;
  if (typeof payload === 'object') {
    const obj = payload as Record<string, unknown>;
    if (typeof obj.error === 'string') return obj.error;
    if (typeof obj.message === 'string') return obj.message;
  }
  return undefined;
}
