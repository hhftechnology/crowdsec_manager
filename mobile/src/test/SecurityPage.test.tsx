import { describe, expect, it } from 'vitest';
import SecurityPage from '@/pages/SecurityPage';

describe('SecurityPage module', () => {
  it('exports a function component', () => {
    expect(typeof SecurityPage).toBe('function');
  });
});
