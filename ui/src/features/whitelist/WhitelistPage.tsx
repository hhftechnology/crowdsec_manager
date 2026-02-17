import { useState } from "react";
import { PageHeader } from "@/components/common/PageHeader";
import { DataTable } from "@/components/common/DataTable";
import { ConfirmDialog } from "@/components/common/ConfirmDialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  useWhitelistQuery,
  useAddWhitelistMutation,
  useQuickWhitelistMutation,
  useRemoveWhitelistMutation,
} from "@/lib/api/whitelist";
import type { WhitelistEntry } from "@/types/models";
import type { ColumnDef } from "@tanstack/react-table";
import { Plus, Zap, Trash2, RefreshCw } from "lucide-react";

export function WhitelistPage() {
  const { data, isLoading, error, refetch } = useWhitelistQuery();
  const addMutation = useAddWhitelistMutation();
  const quickMutation = useQuickWhitelistMutation();
  const removeMutation = useRemoveWhitelistMutation();

  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  const columns: ColumnDef<WhitelistEntry, unknown>[] = [
    {
      accessorKey: "ip",
      header: "IP Address",
      cell: ({ row }) => (
        <span className="font-data">{row.original.ip}</span>
      ),
    },
    {
      accessorKey: "source",
      header: "Source",
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
      accessorKey: "added_at",
      header: "Added At",
      cell: ({ row }) => (
        <span className="font-data text-muted-foreground">
          {row.original.added_at}
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
        title="Whitelist"
        description="Manage whitelisted IP addresses for your proxy"
      >
        <Button
          variant="outline"
          size="sm"
          onClick={() => { quickMutation.mutate(); }}
          disabled={quickMutation.isPending}
        >
          <Zap className="mr-1.5 h-3.5 w-3.5" />
          {quickMutation.isPending ? "Whitelisting..." : "Quick Whitelist My IP"}
        </Button>
      </PageHeader>

      {/* Add form */}
      <div className="card-panel p-4">
        <h2 className="mb-3 text-sm font-medium text-foreground">
          Add IP to Whitelist
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
              placeholder="Trusted server"
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
          <Skeleton className="h-10 w-full" />
        </div>
      ) : error ? (
        <div className="card-panel p-6 text-center">
          <p className="text-sm text-destructive">Failed to load whitelist</p>
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
            No whitelisted IPs. Add one above or use Quick Whitelist.
          </p>
        </div>
      ) : (
        <DataTable columns={columns} data={data ?? []} />
      )}

      <ConfirmDialog
        open={deleteTarget !== null}
        onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}
        title="Remove from Whitelist"
        description={`Are you sure you want to remove ${deleteTarget ?? ""} from the whitelist?`}
        confirmLabel="Remove"
        variant="destructive"
        onConfirm={() => {
          if (deleteTarget) removeMutation.mutate(deleteTarget);
        }}
      />
    </div>
  );
}
