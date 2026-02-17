import { useState } from "react";
import { PageHeader } from "@/components/common/PageHeader";
import { DataTable } from "@/components/common/DataTable";
import { FilterForm } from "@/components/common/FilterForm";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useDecisionsQuery, type DecisionFilters } from "@/lib/api/decisions";
import type { Decision } from "@/types/models";
import type { ColumnDef } from "@tanstack/react-table";
import { RefreshCw } from "lucide-react";

const columns: ColumnDef<Decision, unknown>[] = [
  {
    accessorKey: "id",
    header: "ID",
    cell: ({ row }) => (
      <span className="font-data">{String(row.original.id)}</span>
    ),
  },
  {
    accessorKey: "value",
    header: "Value",
    cell: ({ row }) => (
      <span className="font-data font-medium">{row.original.value}</span>
    ),
  },
  {
    accessorKey: "scope",
    header: "Scope",
  },
  {
    accessorKey: "type",
    header: "Type",
    cell: ({ row }) => (
      <span className="badge-signal rounded-full px-2 py-0.5 text-xs font-medium">
        {row.original.type}
      </span>
    ),
  },
  {
    accessorKey: "origin",
    header: "Origin",
  },
  {
    accessorKey: "scenario",
    header: "Scenario",
    cell: ({ row }) => (
      <span className="font-data text-muted-foreground">
        {row.original.scenario}
      </span>
    ),
  },
  {
    accessorKey: "duration",
    header: "Duration",
    cell: ({ row }) => (
      <span className="font-data text-muted-foreground">
        {row.original.duration}
      </span>
    ),
  },
  {
    accessorKey: "until",
    header: "Until",
    cell: ({ row }) => (
      <span className="font-data text-muted-foreground">
        {row.original.until}
      </span>
    ),
  },
];

export function DecisionsPage() {
  const [filters, setFilters] = useState<DecisionFilters>({});
  const [formIp, setFormIp] = useState("");
  const [formScope, setFormScope] = useState("");
  const [formType, setFormType] = useState("");
  const [formOrigin, setFormOrigin] = useState("");

  const { data, isLoading, error, refetch } = useDecisionsQuery(filters);

  function handleSearch() {
    setFilters({
      ip: formIp || undefined,
      scope: formScope || undefined,
      type: formType || undefined,
      origin: formOrigin || undefined,
    });
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Decisions"
        description="View active CrowdSec decisions (bans, captchas, throttles)"
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
            IP Address
          </label>
          <Input
            placeholder="Filter by IP"
            value={formIp}
            onChange={(e) => { setFormIp(e.target.value); }}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted-foreground">
            Scope
          </label>
          <Input
            placeholder="e.g. Ip, Range"
            value={formScope}
            onChange={(e) => { setFormScope(e.target.value); }}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted-foreground">
            Type
          </label>
          <Input
            placeholder="e.g. ban, captcha"
            value={formType}
            onChange={(e) => { setFormType(e.target.value); }}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs text-muted-foreground">
            Origin
          </label>
          <Input
            placeholder="e.g. cscli, crowdsec"
            value={formOrigin}
            onChange={(e) => { setFormOrigin(e.target.value); }}
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
          <p className="text-sm text-destructive">Failed to load decisions</p>
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
            No active decisions found
          </p>
        </div>
      ) : (
        <DataTable columns={columns} data={data ?? []} />
      )}
    </div>
  );
}
