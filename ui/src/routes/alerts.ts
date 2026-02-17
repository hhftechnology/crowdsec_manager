import { createFileRoute } from "@tanstack/react-router";
import { AlertsPage } from "@/features/alerts/AlertsPage";

export const Route = createFileRoute("/alerts")({
  component: AlertsPage,
});
