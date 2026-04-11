import { AlertCircle, RefreshCw } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import type { AppErrorState } from '@/lib/errors';

type InlineErrorBannerProps = {
  title?: string;
  message: string;
  error?: AppErrorState;
  onRetry?: () => void;
  className?: string;
};

export function InlineErrorBanner({
  title = 'Request failed',
  message,
  error,
  onRetry,
  className,
}: InlineErrorBannerProps) {
  const resolvedTitle = error?.title || title;
  const resolvedMessage = error?.message || message;

  return (
    <Alert variant="destructive" className={className}>
      <AlertCircle className="h-4 w-4" />
      <AlertTitle>{resolvedTitle}</AlertTitle>
      <AlertDescription>
        <div className="space-y-3">
          <p>{resolvedMessage}</p>
          {onRetry && (
            <Button variant="secondary" size="sm" onClick={onRetry} className="gap-1.5">
              <RefreshCw className="h-3 w-3" />
              Retry
            </Button>
          )}
        </div>
      </AlertDescription>
    </Alert>
  );
}
