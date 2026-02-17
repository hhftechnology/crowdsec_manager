import { createFileRoute } from "@tanstack/react-router";
import { BackupsPage } from "@/features/backups/BackupsPage";

export const Route = createFileRoute("/backups")({
  component: BackupsPage,
});
