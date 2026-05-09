import { describe, expect, it } from 'vitest';
import ManagementPage from '@/pages/ManagementPage';

describe('ManagementPage module', () => {
  it('exports a function component', () => {
    expect(typeof ManagementPage).toBe('function');
  });
});
