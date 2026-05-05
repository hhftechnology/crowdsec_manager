import { Skeleton } from '@/components/ui/skeleton';

interface RouteLoadingScreenProps {
  showHeader?: boolean;
}

export function RouteLoadingScreen({ showHeader = true }: RouteLoadingScreenProps) {
  return (
    <div className="pb-nav" aria-label="Loading content">
      {showHeader && (
        <div className="flex items-start justify-between px-md pt-md pb-xs">
          <div className="space-y-xs">
            <Skeleton className="h-8 w-40" />
            <Skeleton className="h-4 w-48" />
          </div>
          <Skeleton className="h-10 w-10 rounded-pill" />
        </div>
      )}

      <div className="px-md space-y-md">
        <div className="grid grid-cols-2 gap-sm">
          {Array.from({ length: 4 }, (_, index) => (
            <div key={index} className="rounded-lg border border-hairline bg-surface-card p-sm space-y-sm">
              <Skeleton className="h-3.5 w-16" />
              <Skeleton className="h-5 w-20" />
            </div>
          ))}
        </div>

        {Array.from({ length: 3 }, (_, index) => (
          <div key={index} className="rounded-lg border border-hairline bg-surface-card p-md space-y-sm">
            <Skeleton className="h-4 w-32" />
            <div className="space-y-xs">
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
