import { Shield, Activity, Container } from "lucide-react";
import { PageHeader } from "@/components/common/PageHeader";

function StatCard({
  label,
  value,
  icon: Icon,
  variant = "default",
}: {
  label: string;
  value: string | number;
  icon: React.ElementType;
  variant?: "default" | "success" | "warning" | "signal";
}) {
  const variantClasses = {
    default: "text-muted-foreground",
    success: "text-success",
    warning: "text-warning",
    signal: "text-signal",
  };

  return (
    <div className="card-panel p-4 md:p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {label}
          </p>
          <p className="mt-1.5 text-2xl font-semibold text-foreground">
            {value}
          </p>
        </div>
        <div className={variantClasses[variant]}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  );
}

function ContainerStatusCard({
  name,
  id,
  status,
}: {
  name: string;
  id: string;
  status: "running" | "stopped" | "error";
}) {
  const statusLabel = {
    running: "Running",
    stopped: "Stopped",
    error: "Error",
  };

  return (
    <div className="card-panel flex items-center justify-between p-4">
      <div className="flex items-center gap-3">
        <div className={`status-dot status-dot--${status}`} />
        <div>
          <p className="text-sm font-medium text-foreground">{name}</p>
          <p className="font-data text-muted-foreground">{id}</p>
        </div>
      </div>
      <span
        className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
          status === "running"
            ? "bg-success/10 text-success"
            : status === "error"
              ? "bg-destructive/10 text-destructive"
              : "bg-muted text-muted-foreground"
        }`}
      >
        {statusLabel[status]}
      </span>
    </div>
  );
}

export function DashboardPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description="System health overview"
      />

      {/* Stats grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <StatCard
          label="Active Decisions"
          value={3}
          icon={Shield}
          variant="signal"
        />
        <StatCard
          label="Active Bouncers"
          value={1}
          icon={Activity}
          variant="success"
        />
        <StatCard
          label="Containers"
          value="4/4"
          icon={Container}
          variant="success"
        />
      </div>

      {/* Container status */}
      <div>
        <h2 className="mb-3 text-sm font-medium text-muted-foreground">
          System Health
        </h2>
        <div className="grid gap-3">
          <ContainerStatusCard
            name="crowdsec"
            id="3ddd68aba4f9"
            status="running"
          />
          <ContainerStatusCard
            name="traefik"
            id="9a9c1d17f0ce"
            status="running"
          />
          <ContainerStatusCard
            name="pangolin"
            id="30768ae13f94"
            status="running"
          />
          <ContainerStatusCard
            name="gerbil"
            id="b5294f9e90ab"
            status="running"
          />
        </div>
      </div>
    </div>
  );
}
