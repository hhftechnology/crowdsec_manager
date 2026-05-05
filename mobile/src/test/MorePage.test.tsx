import { describe, expect, it } from 'vitest';
import MorePage from '@/pages/MorePage';

describe('MorePage module', () => {
  it('exports a function component', () => {
    expect(typeof MorePage).toBe('function');
  });
});
