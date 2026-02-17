import { useState } from "react";
import { PageHeader } from "@/components/common/PageHeader";
import { DataTable } from "@/components/common/DataTable";
import { FilterForm } from "@/components/common/FilterForm";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAlertsQuery, type AlertFilters } from "@/lib/api/alerts";
import type { Alert } from "@/types/models";
import type { ColumnDef } from "@tanstack/react-table";
import { RefreshCw } from "lucide-react";

const columns: ColumnDef<Alert, unknown>[] = [
  {
    accessorKey: "id",
    header: "ID",
    cell: ({ row }) => (
      <span className="font-data">{String(row.original.id)}</span>
    ),
  },
  {
    accessorKey: "scenario",
    header: "Scenario",
    cell: ({ row }) => (
      <span className="font-medium text-foreground">
        {row.original.scenario}
      </span>
    ),
  },
  {
    accessorKey: "source_ip",
    header: "Source IP",
    cell: ({ row }) => (
      <span className="font-data">{row.original.source_ip}</span>
    ),
  },
  {
    accessorKey: "source_scope",
    header: "Scope",
  },
  {
    accessorKey: "events_count",
    header: "Events",
    cell: ({ row }) => (
      <span className="badge-signal rounded-full px-2 py-0.5 text-xs font-medium">
        {String(row.original.events_count)}
      </span>
    ),
  },
  {
    accessorKey: "created_at",
    header: "Created At",
    cell: ({ row }) => (
      <span className="font-data text-muted-foreground">
        {row.original.created_at}
      </span>
    ),
  },
];

export function AlertsPage() {
  const [filters, setFilters] = useState<AlertFilters>({});
  const [formScenario, setFormScenario] = useState("");
  const [formIp, setFormIp] = useState("");
  const [formSince, setFormSince] = useState("");

  const { data, isLoading, error, refetch } = useAlertsQuery(filters);

  function handleSearch() {
    setFilters({
      scenario: formScenario || undefined,
      ip: formIp || undefined,
      since: formSince || undefined,
    });
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Alerts"
        description="View CrowdSec security alerts and triggered scenarios"
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

      <FilterForm onSubmit={handleSearch}>
        <div>
          <label className="mb-1 block text-xs text-muted-foreground">
            Scenario
          </label>
          <Input
            placeholder="Filter by scenario"
            value={formScenario}
            onChange={(e) => { setFormScenario(e.target.value); }}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted-foreground">
            Source IP
          </label>
          <Input
            placeholder="Filter by IP"
            value={formIp}
            onChange={(e) => { setFormIp(e.target.value); }}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted-foreground">
            Since
          </label>
          <Input
            placeholder="e.g. 1h, 24h, 7d"
            value={formSince}
            onChange={(e) => { setFormSince(e.target.value); }}
          />
        </div>
      </FilterForm>

      {isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : error ? (
        <div className="card-panel p-6 text-center">
          <p className="text-sm text-destructive">Failed to load alerts</p>
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
            No alerts found matching the filters
          </p>
        </div>
      ) : (
        <DataTable columns={columns} data={data ?? []} />
      )}
    </div>
  );
}
