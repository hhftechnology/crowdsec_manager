import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Onboarding } from '@/components/Onboarding';

describe('Onboarding', () => {
  it('renders first slide title', () => {
    render(<Onboarding onComplete={vi.fn()} />);
    expect(screen.getByText(/A literary console/i)).toBeInTheDocument();
  });
});
