import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { PageHeader } from '@/components/PageHeader';

describe('PageHeader', () => {
  it('renders title and subtitle', () => {
    render(<PageHeader title="Today, calm." subtitle="3 containers up" />);
    expect(screen.getByRole('heading', { name: 'Today, calm.' })).toBeInTheDocument();
    expect(screen.getByText('3 containers up')).toBeInTheDocument();
  });

  it('renders eyebrow with spike when provided', () => {
    const { container } = render(<PageHeader title="Overview." eyebrow="Overview" />);
    expect(screen.getByText('Overview')).toBeInTheDocument();
    expect(container.querySelector('svg')).toBeTruthy();
  });

  it('uses dark surface when dark prop set', () => {
    const { container } = render(<PageHeader title="x" dark />);
    expect(container.querySelector('header')?.className).toContain('bg-surface-dark');
  });
});
