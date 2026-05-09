import { describe, expect, it } from 'vitest';
import { APP_STORE_URL, PLAY_STORE_URL } from './storeLinks';

describe('storeLinks', () => {
  it('exposes a Play Store URL pointing at the published app id', () => {
    expect(PLAY_STORE_URL).toContain('play.google.com');
    expect(PLAY_STORE_URL).toContain('id=com.crowdsec.manager.mobile');
  });

  it('exposes an App Store URL constant (empty until iOS is published)', () => {
    expect(typeof APP_STORE_URL).toBe('string');
  });
});
