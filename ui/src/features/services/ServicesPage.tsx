import { PageHeader } from "@/components/common/PageHeader";
import { ContainerCard } from "@/components/common/ContainerCard";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import {
  useServicesQuery,
  useStartServiceMutation,
  useStopServiceMutation,
  useRestartServiceMutation,
} from "@/lib/api/services";
import type { Container } from "@/types/models";
import { RefreshCw } from "lucide-react";

export function ServicesPage() {
  const { data, isLoading, error, refetch } = useServicesQuery();
  const startMutation = useStartServiceMutation();
  const stopMutation = useStopServiceMutation();
  const restartMutation = useRestartServiceMutation();

  const containers: Container[] = (data ?? []).map((svc) => ({
    id: svc.container_id,
    name: svc.name,
    image: svc.image,
    state: svc.state,
    status: svc.status,
    health: "none" as const,
  }));

  return (
    <div className="space-y-6">
      <PageHeader
        title="Services"
        description="Manage Docker containers and services"
      >
        <Button
          variant="outline"
          size="sm"
          onClick={() => { void refetch(); }}
          disabled={isLoading}
        >
          <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Refresh
        </Button>
      </PageHeader>

      {isLoading ? (
        <div className="grid gap-3">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
        </div>
      ) : error ? (
        <div className="card-panel p-6 text-center">
          <p className="text-sm text-destructive">Failed to load services</p>
          <Button
            variant="outline"
            size="sm"
            className="mt-3"
            onClick={() => { void refetch(); }}
          >
            <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Retry
          </Button>
        </div>
      ) : containers.length === 0 ? (
        <div className="card-panel p-6 text-center">
          <p className="text-sm text-muted-foreground">No services found</p>
        </div>
      ) : (
        <div className="grid gap-3">
          {containers.map((container) => (
            <ContainerCard
              key={container.id}
              container={container}
              onStart={(name) => { startMutation.mutate(name); }}
              onStop={(name) => { stopMutation.mutate(name); }}
              onRestart={(name) => { restartMutation.mutate(name); }}
            />
          ))}
        </div>
      )}
    </div>
  );
}
