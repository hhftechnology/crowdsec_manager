import { render, screen } from '@testing-library/react';
import HomePage from './page';

jest.mock('@/lib/seo', () => ({ getSiteUrl: () => 'https://crowdsec-manager.hhf.technology' }));
jest.mock('next/link', () => ({ __esModule: true, default: ({ href, children }: { href: string; children: React.ReactNode }) => <a href={href}>{children}</a> }));

describe('HomePage', () => {
  it('renders the hero heading', () => {
    render(<HomePage />);
    expect(screen.getByRole('heading', { name: /crowdsec manager/i })).toBeInTheDocument();
  });

  it('renders mobile app section', () => {
    render(<HomePage />);
    expect(screen.getByText(/mobile app/i)).toBeInTheDocument();
    expect(screen.getByAltText(/app store/i)).toBeInTheDocument();
  });

  it('renders both deployment variant sections', () => {
    render(<HomePage />);
    expect(screen.getByText('Pangolin')).toBeInTheDocument();
    expect(screen.getByText('Independent')).toBeInTheDocument();
  });

  it('renders get started link', () => {
    render(<HomePage />);
    expect(screen.getByRole('link', { name: /get started/i })).toHaveAttribute('href', '/docs/installation');
  });
});
