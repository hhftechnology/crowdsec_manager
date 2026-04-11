import { afterEach, describe, expect, it, vi } from 'vitest';
import { createApi } from '@/lib/api';
import { parseHubItems } from '@/lib/api/hub';

describe('API service route usage', () => {
  const api = createApi('https://api.example.com');

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('uses canonical crowdsec metrics route', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ success: true, data: { parsers: { processed: 1 } } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    await api.crowdsec.metrics();

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://api.example.com/api/crowdsec/metrics',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('uses canonical scenario file delete route', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ success: true, data: null }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    await api.scenarios.deleteFile('custom-scenario.yaml');

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://api.example.com/api/scenarios/file',
      expect.objectContaining({
        method: 'DELETE',
        body: JSON.stringify({ filename: 'custom-scenario.yaml' }),
      }),
    );
  });

  it('sends decision import as multipart form data', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ success: true, data: { output: 'ok' } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    const file = new File(['1.2.3.4,ban,4h'], 'decisions.csv', { type: 'text/csv' });
    await api.crowdsec.importDecisions(file);

    const [, init] = fetchSpy.mock.calls[0] ?? [];
    const requestInit = init as RequestInit;

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://api.example.com/api/crowdsec/decisions/import',
      expect.objectContaining({ method: 'POST' }),
    );
    expect(requestInit.body).toBeInstanceOf(FormData);
  });

  it('uses paged decisions analysis query params', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ success: true, data: { decisions: [], count: 0, total: 0 } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    await api.crowdsec.decisionsAnalysis({ limit: 20, offset: 40, type: 'ban' });

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://api.example.com/api/crowdsec/decisions/analysis?limit=20&offset=40&type=ban',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('uses decision history and reapply routes', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ success: true, data: { decisions: [], count: 0, total: 0 } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ success: true, message: 'ok', data: { message: 'ok' } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );

    await api.crowdsec.decisionHistory({ limit: 20, offset: 20 });
    await api.crowdsec.reapplyDecision({ id: 7, type: 'ban', duration: '24h' });

    expect(fetchSpy).toHaveBeenNthCalledWith(
      1,
      'https://api.example.com/api/crowdsec/decisions/history?limit=20&offset=20',
      expect.objectContaining({ method: 'GET' }),
    );
    expect(fetchSpy).toHaveBeenNthCalledWith(
      2,
      'https://api.example.com/api/crowdsec/decisions/history/reapply',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ id: 7, type: 'ban', duration: '24h' }),
      }),
    );
  });

  it('parses grouped hub payloads from raw JSON', () => {
    const parsed = parseHubItems(
      '{"collections":[{"name":"base/http-cve"}],"scenarios":[{"name":"crowdsecurity/ssh-bf"}]}',
    );

    expect(parsed.rawParseError).toBe(false);
    expect(parsed.groupedItems.collections?.[0]?.name).toBe('base/http-cve');
    expect(parsed.groupedItems.scenarios?.[0]?.name).toBe('crowdsecurity/ssh-bf');
  });
});
