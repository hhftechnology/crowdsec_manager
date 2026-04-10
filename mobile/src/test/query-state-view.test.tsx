import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { QueryStateView } from '@/components/QueryStateView';

describe('QueryStateView', () => {
  it('renders loading fallback', () => {
    render(
      <QueryStateView isLoading error={null}>
        <div>content</div>
      </QueryStateView>,
    );

    expect(screen.getByLabelText('Loading content')).toBeInTheDocument();
  });

  it('renders error banner and hides content', () => {
    render(
      <QueryStateView isLoading={false} error="fetch failed" onRetry={() => {}}>
        <div>content</div>
      </QueryStateView>,
    );

    expect(screen.getByText('fetch failed')).toBeInTheDocument();
    expect(screen.queryByText('content')).not.toBeInTheDocument();
  });

  it('renders normalized error titles when provided', () => {
    render(
      <QueryStateView
        isLoading={false}
        error={{ title: 'API unreachable', message: 'Check server status.', kind: 'unreachable' }}
      >
        <div>content</div>
      </QueryStateView>,
    );

    expect(screen.getByText('API unreachable')).toBeInTheDocument();
    expect(screen.getByText('Check server status.')).toBeInTheDocument();
  });

  it('renders empty state', () => {
    render(
      <QueryStateView isLoading={false} error={null} isEmpty emptyTitle="Nothing here" emptyDescription="Try again later">
        <div>content</div>
      </QueryStateView>,
    );

    expect(screen.getByText('Nothing here')).toBeInTheDocument();
    expect(screen.queryByText('content')).not.toBeInTheDocument();
  });

  it('renders children for success state', () => {
    render(
      <QueryStateView isLoading={false} error={null} isEmpty={false}>
        <div>content</div>
      </QueryStateView>,
    );

    expect(screen.getByText('content')).toBeInTheDocument();
  });
});
