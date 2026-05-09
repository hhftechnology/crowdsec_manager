import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Spike, Wordmark, Pill, UpperBadge, Dot, ButtonPrimary, ButtonSecondary, CategoryTab, FieldLabel, Bars, Donut } from '@/components/design';

describe('design primitives', () => {
  it('renders Spike svg', () => {
    const { container } = render(<Spike />);
    expect(container.querySelector('svg')).toBeTruthy();
  });

  it('renders Wordmark with brand text', () => {
    render(<Wordmark />);
    expect(screen.getByText('Crowdsec')).toBeInTheDocument();
  });

  it('renders Pill with tone classes', () => {
    render(<Pill tone="coral">live</Pill>);
    const el = screen.getByText('live');
    expect(el.className).toContain('bg-primary');
  });

  it('renders UpperBadge uppercase', () => {
    render(<UpperBadge tone="cream">new</UpperBadge>);
    expect(screen.getByText('new').className).toContain('uppercase');
  });

  it('renders Dot with success tone', () => {
    const { container } = render(<Dot tone="success" />);
    expect(container.querySelector('span')?.className).toContain('bg-success');
  });

  it('renders ButtonPrimary as button', () => {
    render(<ButtonPrimary>Connect</ButtonPrimary>);
    expect(screen.getByRole('button', { name: 'Connect' })).toBeInTheDocument();
  });

  it('renders ButtonSecondary dark variant', () => {
    render(<ButtonSecondary dark>Cancel</ButtonSecondary>);
    expect(screen.getByRole('button', { name: 'Cancel' }).className).toContain('bg-surface-dark-elevated');
  });

  it('renders CategoryTab active state', () => {
    render(<CategoryTab active>IP</CategoryTab>);
    expect(screen.getByRole('button', { name: 'IP' }).className).toContain('bg-surface-card');
  });

  it('renders FieldLabel as label element', () => {
    const { container } = render(<FieldLabel>Server URL</FieldLabel>);
    expect(container.querySelector('label')).toBeTruthy();
  });

  it('renders Bars with given values', () => {
    const { container } = render(<Bars values={[1, 2, 3]} />);
    const wrapper = container.firstElementChild as HTMLElement;
    expect(wrapper?.children).toHaveLength(3);
  });

  it('renders Donut svg with segments', () => {
    const { container } = render(<Donut segments={[{ value: 5, color: 'primary' }]} />);
    expect(container.querySelector('svg')).toBeTruthy();
  });

  it('renders only the neutral Donut track when all segments are zero', () => {
    const { container } = render(
      <Donut
        segments={[
          { value: 0, color: 'primary' },
          { value: 0, color: 'accent-amber' },
          { value: 0, color: 'accent-teal' },
        ]}
      />,
    );

    const circles = container.querySelectorAll('circle');
    expect(circles).toHaveLength(1);
    expect(circles[0].className.baseVal).toContain('text-hairline');
    expect(circles[0]).not.toHaveAttribute('stroke-dasharray');
  });
});
