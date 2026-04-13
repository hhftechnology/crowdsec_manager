import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/lib/api';
import { normalizeAppError } from '@/lib/errors';

describe('normalizeAppError', () => {
  it('maps failed fetch to unreachable API message', () => {
    expect(
      normalizeAppError(new TypeError('Failed to fetch'), {
        baseUrl: 'http://10.0.0.1:8080',
      }),
    ).toMatchObject({
      title: 'API unreachable',
      kind: 'unreachable',
    });
  });

  it('maps offline state before transport errors', () => {
    vi.spyOn(window.navigator, 'onLine', 'get').mockReturnValue(false);

    expect(normalizeAppError(new TypeError('Failed to fetch'))).toMatchObject({
      title: 'You are offline',
      kind: 'offline',
    });
  });

  it('maps abort errors to timeout state', () => {
    const abortError = new DOMException('The operation was aborted.', 'AbortError');

    expect(normalizeAppError(abortError)).toMatchObject({
      title: 'Request timed out',
      kind: 'timeout',
    });
  });

  it('preserves backend response messages for API errors', () => {
    expect(normalizeAppError(new ApiError('bad request', 400))).toMatchObject({
      title: 'Request failed',
      message: 'bad request',
      kind: 'server',
    });
  });
});
