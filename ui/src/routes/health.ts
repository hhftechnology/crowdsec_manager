import { createFileRoute } from "@tanstack/react-router";
import { HealthPage } from "@/features/health/HealthPage";

export const Route = createFileRoute("/health")({
  component: HealthPage,
});
