import { useState } from "react";
import { PageHeader } from "@/components/common/PageHeader";
import { StatusBadge } from "@/components/common/StatusBadge";
import { DataTable } from "@/components/common/DataTable";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import {
  useContainersQuery,
  useBouncersQuery,
  useProxyHealthQuery,
} from "@/lib/api/health";
import type { Container, BouncerInfo } from "@/types/models";
import type { ColumnDef } from "@tanstack/react-table";
import {
  Activity,
  Server,
  Shield,
  RefreshCw,
  CheckCircle,
  XCircle,
} from "lucide-react";

type Tab = "containers" | "bouncers" | "proxy";

const containerColumns: ColumnDef<Container, unknown>[] = [
  {
    accessorKey: "name",
    header: "Name",
    cell: ({ row }) => (
      <span className="font-medium text-foreground">
        {row.original.name}
      </span>
    ),
  },
  {
    accessorKey: "id",
    header: "Container ID",
    cell: ({ row }) => (
      <span className="font-data">{row.original.id.slice(0, 12)}</span>
    ),
  },
  {
    accessorKey: "image",
    header: "Image",
    cell: ({ row }) => (
      <span className="font-data text-muted-foreground">
        {row.original.image}
      </span>
    ),
  },
  {
    accessorKey: "state",
    header: "State",
    cell: ({ row }) => {
      const state = row.original.state;
      const status =
        state === "running"
          ? "running"
          : state === "stopped"
            ? "stopped"
            : "error";
      return <StatusBadge status={status} label={state} />;
    },
  },
  {
    accessorKey: "health",
    header: "Health",
    cell: ({ row }) => {
      const h = row.original.health;
      if (h === "healthy")
        return (
          <span className="inline-flex items-center gap-1 text-xs text-success">
            <CheckCircle className="h-3.5 w-3.5" /> Healthy
          </span>
        );
      if (h === "unhealthy")
        return (
          <span className="inline-flex items-center gap-1 text-xs text-destructive">
            <XCircle className="h-3.5 w-3.5" /> Unhealthy
          </span>
        );
      return (
        <span className="text-xs text-muted-foreground">No healthcheck</span>
      );
    },
  },
];

const bouncerColumns: ColumnDef<BouncerInfo, unknown>[] = [
  {
    accessorKey: "name",
    header: "Name",
    cell: ({ row }) => (
      <span className="font-medium text-foreground">
        {row.original.name}
      </span>
    ),
  },
  {
    accessorKey: "ip_address",
    header: "IP Address",
    cell: ({ row }) => (
      <span className="font-data">{row.original.ip_address}</span>
    ),
  },
  {
    accessorKey: "type",
    header: "Type",
  },
  {
    accessorKey: "last_pull",
    header: "Last Pull",
    cell: ({ row }) => (
      <span className="font-data text-muted-foreground">
        {row.original.last_pull}
      </span>
    ),
  },
  {
    accessorKey: "valid",
    header: "Valid",
    cell: ({ row }) => (
      <StatusBadge
        status={row.original.valid ? "running" : "error"}
        label={row.original.valid ? "Valid" : "Invalid"}
      />
    ),
  },
];

export function HealthPage() {
  const [tab, setTab] = useState<Tab>("containers");
  const containers = useContainersQuery();
  const bouncers = useBouncersQuery();
  const proxyHealth = useProxyHealthQuery();

  const tabs: { key: Tab; label: string; icon: React.ElementType }[] = [
    { key: "containers", label: "Containers", icon: Server },
    { key: "bouncers", label: "Bouncers", icon: Shield },
    { key: "proxy", label: "Proxy Integration", icon: Activity },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Health & Diagnostics"
        description="Monitor system health, bouncer status, and proxy integration"
      />

      {/* Tab bar */}
      <div className="flex gap-1 rounded-lg bg-muted p-1">
        {tabs.map((t) => (
          <button
            key={t.key}
            type="button"
            onClick={() => { setTab(t.key); }}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
              tab === t.key
                ? "bg-background text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <t.icon className="h-4 w-4" />
            {t.label}
          </button>
        ))}
      </div>

      {/* Containers tab */}
      {tab === "containers" ? (
        <div className="space-y-4">
          {containers.isLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : containers.error ? (
            <div className="card-panel p-6 text-center">
              <p className="text-sm text-destructive">
                Failed to load containers
              </p>
              <Button
                variant="outline"
                size="sm"
                className="mt-3"
                onClick={() => { void containers.refetch(); }}
              >
                <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Retry
              </Button>
            </div>
          ) : (
            <DataTable
              columns={containerColumns}
              data={containers.data ?? []}
            />
          )}
        </div>
      ) : null}

      {/* Bouncers tab */}
      {tab === "bouncers" ? (
        <div className="space-y-4">
          {bouncers.isLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : bouncers.error ? (
            <div className="card-panel p-6 text-center">
              <p className="text-sm text-destructive">
                Failed to load bouncers
              </p>
              <Button
                variant="outline"
                size="sm"
                className="mt-3"
                onClick={() => { void bouncers.refetch(); }}
              >
                <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Retry
              </Button>
            </div>
          ) : (bouncers.data ?? []).length === 0 ? (
            <div className="card-panel p-6 text-center">
              <p className="text-sm text-muted-foreground">
                No bouncers registered
              </p>
            </div>
          ) : (
            <DataTable columns={bouncerColumns} data={bouncers.data ?? []} />
          )}
        </div>
      ) : null}

      {/* Proxy tab */}
      {tab === "proxy" ? (
        <div className="space-y-4">
          {proxyHealth.isLoading ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <Skeleton className="h-32" />
              <Skeleton className="h-32" />
            </div>
          ) : proxyHealth.error ? (
            <div className="card-panel p-6 text-center">
              <p className="text-sm text-destructive">
                Failed to load proxy health
              </p>
              <Button
                variant="outline"
                size="sm"
                className="mt-3"
                onClick={() => { void proxyHealth.refetch(); }}
              >
                <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Retry
              </Button>
            </div>
          ) : proxyHealth.data ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="card-panel p-5">
                <h3 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Proxy Type
                </h3>
                <p className="mt-1.5 text-lg font-semibold text-foreground">
                  {proxyHealth.data.proxy.name}
                </p>
                <p className="mt-1 font-data text-muted-foreground">
                  {proxyHealth.data.proxy.containerName}
                </p>
              </div>
              <div className="card-panel p-5">
                <h3 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  Features
                </h3>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {proxyHealth.data.proxy.features.map((feature) => (
                    <span
                      key={feature}
                      className="badge-signal rounded-full px-2.5 py-0.5 text-xs font-medium"
                    >
                      {feature}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
