import type { Container } from "@/types/models";
import { StatusBadge } from "./StatusBadge";
import { Button } from "@/components/ui/button";
import { Play, Square, RotateCw } from "lucide-react";

interface ContainerCardProps {
  container: Container;
  onStart?: (name: string) => void;
  onStop?: (name: string) => void;
  onRestart?: (name: string) => void;
}

function mapState(state: Container["state"]): "running" | "stopped" | "error" {
  if (state === "running") return "running";
  if (state === "stopped") return "stopped";
  return "error";
}

export function ContainerCard({
  container,
  onStart,
  onStop,
  onRestart,
}: ContainerCardProps) {
  const status = mapState(container.state);

  return (
    <div className="card-panel flex items-center justify-between p-4">
      <div className="flex items-center gap-3">
        <div className={`status-dot status-dot--${status}`} />
        <div>
          <p className="text-sm font-medium text-foreground">
            {container.name}
          </p>
          <p className="font-data text-muted-foreground">{container.id}</p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <StatusBadge status={status} />
        {(onStart ?? onStop ?? onRestart) ? (
          <div className="ml-2 flex items-center gap-1">
            {onStart && container.state === "stopped" ? (
              <Button
                variant="ghost"
                size="icon"
                onClick={() => { onStart(container.name); }}
                title="Start"
              >
                <Play className="h-4 w-4" />
              </Button>
            ) : null}
            {onStop && container.state === "running" ? (
              <Button
                variant="ghost"
                size="icon"
                onClick={() => { onStop(container.name); }}
                title="Stop"
              >
                <Square className="h-4 w-4" />
              </Button>
            ) : null}
            {onRestart ? (
              <Button
                variant="ghost"
                size="icon"
                onClick={() => { onRestart(container.name); }}
                title="Restart"
              >
                <RotateCw className="h-4 w-4" />
              </Button>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}
