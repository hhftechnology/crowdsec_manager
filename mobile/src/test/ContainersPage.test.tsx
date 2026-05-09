import { describe, expect, it } from 'vitest';
import ContainersPage from '@/pages/ContainersPage';

describe('ContainersPage module', () => {
  it('exports a function component', () => {
    expect(typeof ContainersPage).toBe('function');
  });
});
