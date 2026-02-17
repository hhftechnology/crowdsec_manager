import { createFileRoute } from "@tanstack/react-router";
import { ScenariosPage } from "@/features/scenarios/ScenariosPage";

export const Route = createFileRoute("/scenarios")({
  component: ScenariosPage,
});
