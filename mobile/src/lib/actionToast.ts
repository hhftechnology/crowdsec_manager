import { toast } from '@/hooks/use-toast';
import { ApiError } from '@/lib/api';

export function showActionSuccess(title: string, description?: string) {
  toast({ title, description });
}

export function showActionError(title: string, error: unknown, fallback?: string) {
  const details =
    error instanceof ApiError &&
    error.details &&
    typeof error.details === 'object' &&
    'details' in error.details &&
    typeof (error.details as { details?: unknown }).details === 'string'
      ? (error.details as { details: string }).details
      : undefined;
  const message = error instanceof Error ? error.message : fallback || 'Request failed';
  const description = details ? `${message}\n${details}` : message;
  toast({
    title,
    description,
    variant: 'destructive',
  });
}
