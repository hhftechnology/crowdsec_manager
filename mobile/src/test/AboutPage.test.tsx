import { describe, expect, it } from 'vitest';
import AboutPage from '@/pages/AboutPage';

describe('AboutPage module', () => {
  it('exports a function component', () => {
    expect(typeof AboutPage).toBe('function');
  });
});
