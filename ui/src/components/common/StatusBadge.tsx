import { cn } from "@/lib/utils";

type Status = "running" | "stopped" | "error" | "warning" | "unknown";

interface StatusBadgeProps {
  status: Status;
  label?: string;
}

const statusConfig: Record<Status, { dot: string; bg: string; text: string; defaultLabel: string }> = {
  running: {
    dot: "status-dot--running",
    bg: "bg-success/10",
    text: "text-success",
    defaultLabel: "Running",
  },
  stopped: {
    dot: "status-dot--stopped",
    bg: "bg-muted",
    text: "text-muted-foreground",
    defaultLabel: "Stopped",
  },
  error: {
    dot: "status-dot--error",
    bg: "bg-destructive/10",
    text: "text-destructive",
    defaultLabel: "Error",
  },
  warning: {
    dot: "",
    bg: "bg-warning/10",
    text: "text-warning",
    defaultLabel: "Warning",
  },
  unknown: {
    dot: "",
    bg: "bg-muted",
    text: "text-muted-foreground",
    defaultLabel: "Unknown",
  },
};

export function StatusBadge({ status, label }: StatusBadgeProps) {
  const config = statusConfig[status];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium",
        config.bg,
        config.text,
      )}
    >
      {config.dot ? <span className={cn("status-dot", config.dot)} /> : null}
      {label ?? config.defaultLabel}
    </span>
  );
}
