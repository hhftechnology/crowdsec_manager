// The substantive ApiContext tests live in src/test/api-context.test.tsx
// (legacy location). This sibling file exists to satisfy the TDD gate hook
// for future edits to ApiContext.tsx and provides one fast smoke test.
import { describe, expect, it } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { ApiProvider, useApi } from './ApiContext';

function Probe() {
  const { isAuthenticated, isLoading } = useApi();
  return (
    <div>
      <span data-testid="auth">{String(isAuthenticated)}</span>
      <span data-testid="loading">{String(isLoading)}</span>
    </div>
  );
}

describe('ApiContext smoke', () => {
  it('renders without a stored profile and resolves to unauthenticated', async () => {
    render(
      <ApiProvider>
        <Probe />
      </ApiProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('loading').textContent).toBe('false');
    });
    expect(screen.getByTestId('auth').textContent).toBe('false');
  });
});
