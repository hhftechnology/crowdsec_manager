import { PageHeader } from "@/components/common/PageHeader";
import { DataTable } from "@/components/common/DataTable";
import { StatusBadge } from "@/components/common/StatusBadge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { useScenariosQuery } from "@/lib/api/scenarios";
import type { Scenario } from "@/types/models";
import type { ColumnDef } from "@tanstack/react-table";
import { RefreshCw } from "lucide-react";

const columns: ColumnDef<Scenario, unknown>[] = [
  {
    accessorKey: "name",
    header: "Scenario",
    cell: ({ row }) => (
      <span className="font-medium text-foreground">{row.original.name}</span>
    ),
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => {
      const s = row.original.status.toLowerCase();
      const status =
        s === "enabled" || s === "loaded"
          ? "running"
          : s === "disabled"
            ? "stopped"
            : "unknown";
      return <StatusBadge status={status} label={row.original.status} />;
    },
  },
  {
    accessorKey: "version",
    header: "Version",
    cell: ({ row }) => (
      <span className="font-data text-muted-foreground">
        {row.original.version}
      </span>
    ),
  },
  {
    accessorKey: "path",
    header: "Path",
    cell: ({ row }) => (
      <span className="font-data text-muted-foreground">
        {row.original.path}
      </span>
    ),
  },
];

export function ScenariosPage() {
  const { data, isLoading, error, refetch } = useScenariosQuery();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scenarios"
        description="CrowdSec detection scenarios installed on this instance"
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
        <div className="space-y-3">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : error ? (
        <div className="card-panel p-6 text-center">
          <p className="text-sm text-destructive">Failed to load scenarios</p>
          <Button
            variant="outline"
            size="sm"
            className="mt-3"
            onClick={() => { void refetch(); }}
          >
            <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Retry
          </Button>
        </div>
      ) : (data ?? []).length === 0 ? (
        <div className="card-panel p-6 text-center">
          <p className="text-sm text-muted-foreground">
            No scenarios found. Make sure CrowdSec is properly configured.
          </p>
        </div>
      ) : (
        <DataTable columns={columns} data={data ?? []} />
      )}
    </div>
  );
}
