import { describe, expect, it } from 'vitest';
import LoginPage from '@/pages/LoginPage';

describe('LoginPage module', () => {
  it('exports a function component', () => {
    expect(typeof LoginPage).toBe('function');
  });
});
