import { Loader2 } from 'lucide-react';

type FullScreenLoaderProps = {
  message?: string;
};

export function FullScreenLoader({ message = 'Loading...' }: FullScreenLoaderProps) {
  return (
    <div className="min-h-screen flex items-center justify-center bg-canvas px-lg">
      <div className="flex items-center gap-xs text-body-sm text-muted">
        <Loader2 className="h-4 w-4 animate-spin" />
        <span>{message}</span>
      </div>
    </div>
  );
}
