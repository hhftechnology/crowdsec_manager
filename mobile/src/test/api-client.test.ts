import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiClient, ApiError } from '@/lib/api/client';
import type { ConnectionProfile } from '@/lib/connection';

function createProfile(
  overrides: Partial<ConnectionProfile> = {},
): ConnectionProfile {
  return {
    mode: 'direct',
    baseUrl: 'https://api.example.com',
    allowInsecure: false,
    proxyUsername: '',
    proxyPassword: '',
    pangolinToken: '',
    pangolinTokenParam: 'p_token',
    ...overrides,
  };
}

describe('ApiClient', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('unwraps standard API envelope', async () => {
    const client = new ApiClient(createProfile());
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          success: true,
          message: 'ok',
          data: { value: 42 },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    const res = await client.get<{ value: number }>('/api/test');

    expect(res.data.value).toBe(42);
    expect(res.message).toBe('ok');
  });

  it('throws ApiError for API envelope failure', async () => {
    const client = new ApiClient(createProfile());
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      new Response(JSON.stringify({ success: false, error: 'nope' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    try {
      await client.get('/api/test');
      throw new Error('expected request to fail');
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      expect(error).toMatchObject({ message: 'nope' });
    }
  });

  it('adds query params and parses text response', async () => {
    const client = new ApiClient(createProfile());
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('plain text', {
        status: 200,
        headers: { 'Content-Type': 'text/plain' },
      }),
    );

    const res = await client.get<string>('/api/logs/service', {
      params: { tail: 100, level: 'warn' },
      responseType: 'text',
    });

    expect(res.data).toBe('plain text');
    expect(fetchSpy).toHaveBeenCalledWith(
      'https://api.example.com/api/logs/service?tail=100&level=warn',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('throws ApiError for non-2xx status', async () => {
    const client = new ApiClient(createProfile());
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'bad request' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    await expect(client.get('/api/test')).rejects.toMatchObject({
      message: 'bad request',
      status: 400,
    });
  });

  it('adds basic auth headers for proxy mode', async () => {
    const client = new ApiClient(
      createProfile({
        mode: 'proxy-basic',
        proxyUsername: 'alice',
        proxyPassword: 'secret',
      }),
    );
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ success: true, data: { ok: true } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    await client.get('/api/test');

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://api.example.com/api/test',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Basic YWxpY2U6c2VjcmV0',
        }),
      }),
    );
  });

  it('adds Pangolin access token headers on every HTTP request', async () => {
    const client = new ApiClient(
      createProfile({
        mode: 'pangolin',
        pangolinToken: 'pp6evkhe.3kyqq4a7eay6rp6ow6dacallhm',
        pangolinTokenParam: 'custom_token',
      }),
    );
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ success: true, data: { ok: true } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    await client.get('/api/test');

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://api.example.com/api/test',
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          'P-Access-Token-Id': 'pp6evkhe',
          'P-Access-Token': '3kyqq4a7eay6rp6ow6dacallhm',
        }),
      }),
    );
  });

  it('embeds proxy credentials in websocket urls', () => {
    const client = new ApiClient(
      createProfile({
        mode: 'proxy-basic',
        proxyUsername: 'alice',
        proxyPassword: 'secret',
      }),
    );

    expect(client.getWebSocketUrl('/api/terminal/crowdsec')).toBe(
      'wss://alice:secret@api.example.com/api/terminal/crowdsec',
    );
  });

  it('adds Pangolin access token query params to websocket urls', () => {
    const client = new ApiClient(
      createProfile({
        mode: 'pangolin',
        pangolinToken: 'pp6evkhe.3kyqq4a7eay6rp6ow6dacallhm',
        pangolinTokenParam: 'custom_token',
      }),
    );

    expect(client.getWebSocketUrl('/api/terminal/crowdsec')).toBe(
      'wss://api.example.com/api/terminal/crowdsec?custom_token=pp6evkhe.3kyqq4a7eay6rp6ow6dacallhm',
    );
  });
});
