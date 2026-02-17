import { createFileRoute } from "@tanstack/react-router";
import { AllowlistPage } from "@/features/allowlist/AllowlistPage";

export const Route = createFileRoute("/allowlist")({
  component: AllowlistPage,
});
