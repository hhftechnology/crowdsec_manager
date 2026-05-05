import { describe, expect, it } from 'vitest';
import ScenariosPage from '@/pages/ScenariosPage';

describe('ScenariosPage module', () => {
  it('exports a function component', () => {
    expect(typeof ScenariosPage).toBe('function');
  });
});
