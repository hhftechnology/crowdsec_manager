import { useState } from "react";
import { PageHeader } from "@/components/common/PageHeader";
import { DataTable } from "@/components/common/DataTable";
import { ConfirmDialog } from "@/components/common/ConfirmDialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  useAllowlistQuery,
  useAddAllowlistMutation,
  useRemoveAllowlistMutation,
} from "@/lib/api/allowlist";
import type { AllowlistEntry } from "@/types/models";
import type { ColumnDef } from "@tanstack/react-table";
import { Plus, Trash2, RefreshCw, Info } from "lucide-react";

export function AllowlistPage() {
  const { data, isLoading, error, refetch } = useAllowlistQuery();
  const addMutation = useAddAllowlistMutation();
  const removeMutation = useRemoveAllowlistMutation();

  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  const columns: ColumnDef<AllowlistEntry, unknown>[] = [
    {
      accessorKey: "ip",
      header: "IP Address",
      cell: ({ row }) => (
        <span className="font-data">{row.original.ip}</span>
      ),
    },
    {
      accessorKey: "reason",
      header: "Reason",
      cell: ({ row }) => (
        <span className="text-muted-foreground">
          {row.original.reason ?? "-"}
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
    {
      id: "actions",
      header: "",
      cell: ({ row }) => (
        <Button
          variant="ghost"
          size="icon"
          onClick={() => { setDeleteTarget(row.original.ip); }}
        >
          <Trash2 className="h-4 w-4 text-destructive" />
        </Button>
      ),
    },
  ];

  function handleAdd() {
    if (!ip) return;
    addMutation.mutate(
      { ip, reason: reason || undefined },
      {
        onSuccess: () => {
          setIp("");
          setReason("");
        },
      },
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Allowlist"
        description="Manage CrowdSec allowlist entries (parser-level whitelist)"
      />

      {/* Help text */}
      <div className="card-panel flex items-start gap-3 p-4">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-info" />
        <p className="text-sm text-muted-foreground">
          The allowlist prevents CrowdSec from creating decisions for
          whitelisted IPs at the parser level. This is different from the proxy
          whitelist which operates at the bouncer level.
        </p>
      </div>

      {/* Add form */}
      <div className="card-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-foreground">
          Add IP to Allowlist
        </h2>
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1">
            <label className="mb-1 block text-xs text-muted-foreground">
              IP Address
            </label>
            <Input
              placeholder="192.168.1.1 or CIDR"
              value={ip}
              onChange={(e) => { setIp(e.target.value); }}
            />
          </div>
          <div className="flex-1">
            <label className="mb-1 block text-xs text-muted-foreground">
              Reason (optional)
            </label>
            <Input
              placeholder="Internal network"
              value={reason}
              onChange={(e) => { setReason(e.target.value); }}
            />
          </div>
          <Button
            size="sm"
            onClick={handleAdd}
            disabled={!ip || addMutation.isPending}
          >
            <Plus className="mr-1.5 h-3.5 w-3.5" />
            {addMutation.isPending ? "Adding..." : "Add"}
          </Button>
        </div>
        {addMutation.error ? (
          <p className="mt-2 text-xs text-destructive">
            {addMutation.error.message}
          </p>
        ) : null}
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : error ? (
        <div className="card-panel p-6 text-center">
          <p className="text-sm text-destructive">Failed to load allowlist</p>
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
            No allowlist entries. Add one above to get started.
          </p>
        </div>
      ) : (
        <DataTable columns={columns} data={data ?? []} />
      )}

      <ConfirmDialog
        open={deleteTarget !== null}
        onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}
        title="Remove from Allowlist"
        description={`Are you sure you want to remove ${deleteTarget ?? ""} from the allowlist?`}
        confirmLabel="Remove"
        variant="destructive"
        onConfirm={() => {
          if (deleteTarget) removeMutation.mutate(deleteTarget);
        }}
      />
    </div>
  );
}
