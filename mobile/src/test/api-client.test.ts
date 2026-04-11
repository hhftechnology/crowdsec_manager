import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiClient, ApiError } from '@/lib/api/client';

describe('ApiClient', () => {
  const client = new ApiClient('https://api.example.com');

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('unwraps standard API envelope', async () => {
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
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'bad request' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    await expect(client.get('/api/test')).rejects.toMatchObject({ message: 'bad request', status: 400 });
  });
});
