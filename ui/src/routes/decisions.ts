import { createFileRoute } from "@tanstack/react-router";
import { DecisionsPage } from "@/features/decisions/DecisionsPage";

export const Route = createFileRoute("/decisions")({
  component: DecisionsPage,
});
