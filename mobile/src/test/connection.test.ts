import { describe, expect, it } from 'vitest';
import {
  buildConnectionCandidates,
  isConnectionDraftComplete,
  normalizeConnectionProfileDraft,
  normalizeUrlInput,
  parsePangolinAccessToken,
} from '@/lib/connection';

describe('connection helpers', () => {
  it('parses Pangolin access tokens in tokenId.tokenSecret format', () => {
    expect(
      parsePangolinAccessToken('pp6evkhe.3kyqq4a7eay6rp6ow6dacallhm'),
    ).toEqual({
      id: 'pp6evkhe',
      token: '3kyqq4a7eay6rp6ow6dacallhm',
      combined: 'pp6evkhe.3kyqq4a7eay6rp6ow6dacallhm',
    });
  });

  it('rejects malformed Pangolin tokens', () => {
    expect(parsePangolinAccessToken('missingdot')).toBeNull();
    expect(parsePangolinAccessToken('.secret')).toBeNull();
    expect(parsePangolinAccessToken('token.')).toBeNull();
  });

  it('normalizes url input by trimming and removing trailing slashes', () => {
    expect(normalizeUrlInput('  https://example.com/path///  ')).toBe(
      'https://example.com/path',
    );
  });

  it('builds https-first candidates and only adds http when insecure mode is enabled', () => {
    expect(buildConnectionCandidates('example.com:8080', false)).toEqual([
      'https://example.com:8080',
    ]);
    expect(buildConnectionCandidates('example.com:8080', true)).toEqual([
      'https://example.com:8080',
      'http://example.com:8080',
    ]);
  });

  it('requires mode-specific fields before a draft is complete', () => {
    expect(
      isConnectionDraftComplete(
        normalizeConnectionProfileDraft({
          mode: 'proxy-basic',
          baseUrl: 'proxy.example.com',
        }),
      ),
    ).toBe(false);

    expect(
      isConnectionDraftComplete(
        normalizeConnectionProfileDraft({
          mode: 'pangolin',
          baseUrl: 'pangolin.example.com',
          pangolinToken: 'badtoken',
        }),
      ),
    ).toBe(false);

    expect(
      isConnectionDraftComplete(
        normalizeConnectionProfileDraft({
          mode: 'pangolin',
          baseUrl: 'pangolin.example.com',
          pangolinToken: 'pp6evkhe.secret',
        }),
      ),
    ).toBe(true);
  });
});
