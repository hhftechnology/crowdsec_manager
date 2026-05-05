import { describe, expect, it } from 'vitest';
import HubPage from '@/pages/HubPage';

describe('HubPage module', () => {
  it('exports a function component', () => {
    expect(typeof HubPage).toBe('function');
  });
});
