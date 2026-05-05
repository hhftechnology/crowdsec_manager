import { describe, expect, it } from 'vitest';
import DashboardPage from '@/pages/DashboardPage';

describe('DashboardPage module', () => {
  it('exports a function component', () => {
    expect(typeof DashboardPage).toBe('function');
  });
});
