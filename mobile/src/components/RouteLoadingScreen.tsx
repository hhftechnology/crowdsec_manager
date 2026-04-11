import { Skeleton } from '@/components/ui/skeleton';

interface RouteLoadingScreenProps {
  showHeader?: boolean;
}

export function RouteLoadingScreen({ showHeader = true }: RouteLoadingScreenProps) {
  return (
    <div className="pb-nav" aria-label="Loading content">
      {showHeader && (
        <div className="flex items-start justify-between px-4 pt-4 pb-2">
          <div className="space-y-2">
            <Skeleton className="h-8 w-40" />
            <Skeleton className="h-4 w-48" />
          </div>
          <Skeleton className="h-10 w-10 rounded-full" />
        </div>
      )}

      <div className="px-4 space-y-4">
        <div className="grid grid-cols-2 gap-3">
          {Array.from({ length: 4 }, (_, index) => (
            <div key={index} className="rounded-xl border border-border bg-card p-3 space-y-3">
              <Skeleton className="h-3.5 w-16" />
              <Skeleton className="h-5 w-20" />
            </div>
          ))}
        </div>

        {Array.from({ length: 3 }, (_, index) => (
          <div key={index} className="rounded-xl border border-border bg-card p-4 space-y-3">
            <Skeleton className="h-4 w-32" />
            <div className="space-y-2">
              <Skeleton className="h-3 w-full" />
              <Skeleton className="h-3 w-5/6" />
              <Skeleton className="h-3 w-4/6" />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
