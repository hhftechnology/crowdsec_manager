import { Skeleton } from '@/components/ui/skeleton';

interface DashboardSkeletonProps {
  showHeader?: boolean;
}

export function DashboardSkeleton({ showHeader = false }: DashboardSkeletonProps) {
  return (
    <div className="space-y-md" aria-label="Loading dashboard">
      {showHeader && (
        <div className="space-y-xs px-md pt-md pb-xs">
          <Skeleton className="h-8 w-40" />
          <Skeleton className="h-4 w-52" />
        </div>
      )}

      <div className="grid grid-cols-2 gap-sm">
        {Array.from({ length: 4 }, (_, index) => (
          <div key={index} className="rounded-lg border border-hairline bg-surface-card p-sm space-y-sm">
            <div className="flex items-center gap-xs">
              <Skeleton className="h-3.5 w-3.5 rounded-pill" />
              <Skeleton className="h-3.5 w-16" />
            </div>
            <Skeleton className="h-5 w-24" />
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-hairline bg-surface-card p-md space-y-md">
        <Skeleton className="h-4 w-32" />
        <div className="grid grid-cols-2 gap-sm">
          <Skeleton className="h-16 w-full rounded-lg" />
          <Skeleton className="h-16 w-full rounded-lg" />
        </div>
        <div className="space-y-xs">
          <Skeleton className="h-3 w-full" />
          <Skeleton className="h-3 w-5/6" />
          <Skeleton className="h-3 w-3/4" />
        </div>
      </div>

      {Array.from({ length: 3 }, (_, index) => (
        <div key={index} className="rounded-lg border border-hairline bg-surface-card p-md space-y-sm">
          <div className="flex items-center justify-between">
            <Skeleton className="h-4 w-28" />
            <Skeleton className="h-5 w-20 rounded-pill" />
          </div>
          <div className="space-y-xs">
            <Skeleton className="h-3 w-full" />
            <Skeleton className="h-3 w-11/12" />
            <Skeleton className="h-3 w-4/5" />
          </div>
        </div>
      ))}
    </div>
  );
}
