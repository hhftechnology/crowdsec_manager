import { toast } from '@/hooks/use-toast';

export function showActionSuccess(title: string, description?: string) {
  toast({ title, description });
}

export function showActionError(title: string, error: unknown, fallback?: string) {
  const description = error instanceof Error ? error.message : fallback || 'Request failed';
  toast({
    title,
    description,
    variant: 'destructive',
  });
}
