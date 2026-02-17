import { createFileRoute } from "@tanstack/react-router";
import { WhitelistPage } from "@/features/whitelist/WhitelistPage";

export const Route = createFileRoute("/whitelist")({
  component: WhitelistPage,
});
