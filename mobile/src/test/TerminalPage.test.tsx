import { describe, expect, it } from 'vitest';
import TerminalPage from '@/pages/TerminalPage';

describe('TerminalPage module', () => {
  it('exports a function component', () => {
    expect(typeof TerminalPage).toBe('function');
  });
});
