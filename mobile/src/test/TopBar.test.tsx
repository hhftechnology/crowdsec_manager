import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { TopBar } from '@/components/TopBar';

describe('TopBar', () => {
  it('renders title and back button by default', () => {
    render(
      <MemoryRouter>
        <TopBar title="Allowlists" />
      </MemoryRouter>,
    );
    expect(screen.getByText('Allowlists')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /back/i })).toBeInTheDocument();
  });

  it('omits back button when back=false', () => {
    render(
      <MemoryRouter>
        <TopBar title="404" back={false} />
      </MemoryRouter>,
    );
    expect(screen.queryByRole('button', { name: /back/i })).not.toBeInTheDocument();
  });

  it('invokes custom onBack handler', () => {
    const onBack = vi.fn();
    render(
      <MemoryRouter>
        <TopBar title="x" onBack={onBack} />
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole('button', { name: /back/i }));
    expect(onBack).toHaveBeenCalledTimes(1);
  });
});
