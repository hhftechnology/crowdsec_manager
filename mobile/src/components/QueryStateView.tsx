import type { ReactNode } from 'react';
import { EmptyStateCard } from '@/components/EmptyStateCard';
import { InlineErrorBanner } from '@/components/InlineErrorBanner';
import { RouteLoadingScreen } from '@/components/RouteLoadingScreen';
import type { AppErrorState } from '@/lib/errors';

interface QueryStateViewProps {
  isLoading: boolean;
  error?: string | AppErrorState | null;
  isEmpty?: boolean;
  loadingFallback?: ReactNode;
  emptyTitle?: string;
  emptyDescription?: string;
  onRetry?: () => void;
  children: ReactNode;
}

export function QueryStateView({
  isLoading,
  error,
  isEmpty,
  loadingFallback,
  emptyTitle = 'No data found',
  emptyDescription = 'Nothing to show right now.',
  onRetry,
  children,
}: QueryStateViewProps) {
  if (isLoading) {
    return <>{loadingFallback ?? <RouteLoadingScreen showHeader={false} />}</>;
  }

  if (error) {
    if (typeof error === 'string') {
      return <InlineErrorBanner message={error} onRetry={onRetry} />;
    }
    return <InlineErrorBanner message={error.message} error={error} onRetry={onRetry} />;
  }

  if (isEmpty) {
    return <EmptyStateCard title={emptyTitle} description={emptyDescription} />;
  }

  return <>{children}</>;
}
