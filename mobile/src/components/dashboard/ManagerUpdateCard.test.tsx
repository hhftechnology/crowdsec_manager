import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';

const dismissMock = vi.fn();
let summary = {
  available: true,
  currentVersion: '1.0.0',
  latestVersion: '1.2.0',
  releaseUrl: 'https://github.com/x/y/releases/tag/v1.2.0',
  releaseName: 'v1.2.0',
  publishedAt: '2026-01-01T00:00:00Z',
  installUrl: 'https://github.com/x/y/releases/tag/v1.2.0',
  dismissed: false,
  dismiss: dismissMock,
  isLoading: false,
};

vi.mock('@/hooks/useManagerUpdate', () => ({
  useManagerUpdate: () => summary,
}));

import { ManagerUpdateCard } from './ManagerUpdateCard';

beforeEach(() => {
  dismissMock.mockReset();
  summary = {
    available: true,
    currentVersion: '1.0.0',
    latestVersion: '1.2.0',
    releaseUrl: 'https://github.com/x/y/releases/tag/v1.2.0',
    releaseName: 'v1.2.0',
    publishedAt: '2026-01-01T00:00:00Z',
    installUrl: 'https://github.com/x/y/releases/tag/v1.2.0',
    dismissed: false,
    dismiss: dismissMock,
    isLoading: false,
  };
});

afterEach(() => {
  vi.clearAllMocks();
});

// Unmock + reset under isolate:false so the next test file gets the real hook.
afterAll(() => {
  vi.doUnmock('@/hooks/useManagerUpdate');
  vi.resetModules();
});

describe('ManagerUpdateCard', () => {
  it('renders the latest version and the install link', () => {
    render(<ManagerUpdateCard />);
    expect(screen.getByText(/Update Available/i)).toBeInTheDocument();
    expect(screen.getByText(/1\.2\.0/)).toBeInTheDocument();
    const link = screen.getByRole('link', { name: /update/i });
    expect(link).toHaveAttribute(
      'href',
      'https://github.com/x/y/releases/tag/v1.2.0',
    );
    expect(link).toHaveAttribute('target', '_blank');
  });

  it('invokes dismiss when the close button is clicked', () => {
    render(<ManagerUpdateCard />);
    fireEvent.click(screen.getByLabelText(/dismiss/i));
    expect(dismissMock).toHaveBeenCalledTimes(1);
  });

  it('renders nothing when no update is available', () => {
    summary = { ...summary, available: false };
    const { container } = render(<ManagerUpdateCard />);
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing when dismissed', () => {
    summary = { ...summary, dismissed: true };
    const { container } = render(<ManagerUpdateCard />);
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing while the current version is still loading', () => {
    summary = { ...summary, currentVersion: null, available: false };
    const { container } = render(<ManagerUpdateCard />);
    expect(container).toBeEmptyDOMElement();
  });
});
