import { parsePangolinAccessToken, type ConnectionProfile } from '@/lib/connection';
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

export interface WebSocketUrlOptions {
  forceRefreshAuth?: boolean;
}

function buildQuery(params?: RequestOptions['params']): string {
  if (!params) return '';
  const q = new URLSearchParams();

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    q.set(key, String(value));
  }

  const out = q.toString();
  return out ? '?' + out : '';
}

function normalizePath(path: string): string {
  return path.startsWith('/') ? path : '/' + path;
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

function encodeBasicCredentials(username: string, password: string): string {
  return btoa(username + ':' + password);
}

export class ApiClient {
  readonly profile: ConnectionProfile;
  private readonly baseUrl: string;

  constructor(profile: ConnectionProfile) {
    this.profile = profile;
    this.baseUrl = normalizeBaseUrl(profile.baseUrl);
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

  async verifyConnection(): Promise<void> {
    await this.get('/api/health/stack');
  }

  async ensurePangolinSession(_forceRefresh = false): Promise<void> {
    return;
  }

  async getWebSocketUrl(path: string, params?: RequestOptions['params'], _options?: WebSocketUrlOptions): Promise<string> {
    const parsed = this.buildUrl(path, this.decoratePangolinParams(params));
    parsed.protocol = parsed.protocol === 'https:' ? 'wss:' : 'ws:';

    if (this.isProxyBasicMode()) {
      parsed.username = this.profile.proxyUsername;
      parsed.password = this.profile.proxyPassword;
    }

    return parsed.toString();
  }

  isPangolinMode(): boolean {
    return this.profile.mode === 'pangolin';
  }

  private isProxyBasicMode(): boolean {
    return this.profile.mode === 'proxy-basic';
  }

  private buildUrl(path: string, params?: RequestOptions['params']): URL {
    return new URL(this.baseUrl + normalizePath(path) + buildQuery(params));
  }

  private async request<T>(method: string, path: string, options?: MutationOptions): Promise<ApiResult<T>> {
    const requestUrl = this.buildUrl(path, this.decoratePangolinParams(options?.params)).toString();
    const headers: Record<string, string> = {
      ...(options?.headers ?? {}),
    };

    if (this.isProxyBasicMode()) {
      headers.Authorization = 'Basic ' + encodeBasicCredentials(this.profile.proxyUsername, this.profile.proxyPassword);
    }

    if (this.isPangolinMode()) {
      const token = parsePangolinAccessToken(this.profile.pangolinToken);
      if (token) {
        headers['P-Access-Token-Id'] = token.id;
        headers['P-Access-Token'] = token.token;
      }
    }

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
    const payload = await this.readResponsePayload(response, options?.responseType ?? 'json');

    if (!response.ok) {
      const message = extractErrorMessage(payload) || response.status + ' ' + response.statusText;
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

  private decoratePangolinParams(params?: RequestOptions['params']): RequestOptions['params'] {
    if (!this.isPangolinMode()) return params;

    const token = parsePangolinAccessToken(this.profile.pangolinToken);
    if (!token) return params;

    return {
      ...(params ?? {}),
      [this.profile.pangolinTokenParam]: token.combined,
    };
  }

  private async readResponsePayload(response: Response, responseType: 'json' | 'text'): Promise<unknown> {
    const contentType = response.headers.get('content-type') || '';
    const shouldTreatAsText = responseType === 'text' || contentType.includes('text/plain');

    if (shouldTreatAsText) {
      return response.text();
    }

    const raw = await response.text();
    return raw ? safeJsonParse(raw) : undefined;
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
