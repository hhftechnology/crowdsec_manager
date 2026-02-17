import { useState } from "react";
import { PageHeader } from "@/components/common/PageHeader";
import { DataTable } from "@/components/common/DataTable";
import { ConfirmDialog } from "@/components/common/ConfirmDialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import {
  useBackupsQuery,
  useCreateBackupMutation,
  useRestoreBackupMutation,
  useDeleteBackupMutation,
  useCleanupBackupsMutation,
} from "@/lib/api/backups";
import type { BackupInfo } from "@/types/models";
import type { ColumnDef } from "@tanstack/react-table";
import {
  Plus,
  RotateCw,
  Trash2,
  RefreshCw,
  Archive,
  Download,
} from "lucide-react";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const size = sizes[i];
  if (!size) return `${String(bytes)} B`;
  return `${(bytes / k ** i).toFixed(1)} ${size}`;
}

export function BackupsPage() {
  const { data, isLoading, error, refetch } = useBackupsQuery();
  const createMutation = useCreateBackupMutation();
  const restoreMutation = useRestoreBackupMutation();
  const deleteMutation = useDeleteBackupMutation();
  const cleanupMutation = useCleanupBackupsMutation();

  const [restoreTarget, setRestoreTarget] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  const columns: ColumnDef<BackupInfo, unknown>[] = [
    {
      accessorKey: "name",
      header: "Backup Name",
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Archive className="h-4 w-4 text-muted-foreground" />
          <span className="font-data font-medium">{row.original.name}</span>
        </div>
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
      accessorKey: "size",
      header: "Size",
      cell: ({ row }) => (
        <span className="font-data text-muted-foreground">
          {formatBytes(row.original.size)}
        </span>
      ),
    },
    {
      id: "actions",
      header: "",
      cell: ({ row }) => (
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => { setRestoreTarget(row.original.name); }}
            title="Restore"
          >
            <Download className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => { setDeleteTarget(row.original.name); }}
            title="Delete"
          >
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Backups"
        description="Create, restore, and manage CrowdSec configuration backups"
      >
        <Button
          variant="outline"
          size="sm"
          onClick={() => { cleanupMutation.mutate(); }}
          disabled={cleanupMutation.isPending}
        >
          <RotateCw className="mr-1.5 h-3.5 w-3.5" />
          {cleanupMutation.isPending ? "Cleaning..." : "Cleanup Old"}
        </Button>
        <Button
          size="sm"
          onClick={() => { createMutation.mutate(); }}
          disabled={createMutation.isPending}
        >
          <Plus className="mr-1.5 h-3.5 w-3.5" />
          {createMutation.isPending ? "Creating..." : "Create Backup"}
        </Button>
      </PageHeader>

      {createMutation.error ? (
        <div className="card-panel p-3">
          <p className="text-xs text-destructive">
            {createMutation.error.message}
          </p>
        </div>
      ) : null}

      {isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : error ? (
        <div className="card-panel p-6 text-center">
          <p className="text-sm text-destructive">Failed to load backups</p>
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
            No backups found. Create your first backup above.
          </p>
        </div>
      ) : (
        <DataTable columns={columns} data={data ?? []} />
      )}

      <ConfirmDialog
        open={restoreTarget !== null}
        onOpenChange={(open) => { if (!open) setRestoreTarget(null); }}
        title="Restore Backup"
        description={`Are you sure you want to restore the backup "${restoreTarget ?? ""}"? This will overwrite current configuration.`}
        confirmLabel="Restore"
        onConfirm={() => {
          if (restoreTarget) restoreMutation.mutate(restoreTarget);
        }}
      />

      <ConfirmDialog
        open={deleteTarget !== null}
        onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}
        title="Delete Backup"
        description={`Are you sure you want to permanently delete the backup "${deleteTarget ?? ""}"?`}
        confirmLabel="Delete"
        variant="destructive"
        onConfirm={() => {
          if (deleteTarget) deleteMutation.mutate(deleteTarget);
        }}
      />
    </div>
  );
}
