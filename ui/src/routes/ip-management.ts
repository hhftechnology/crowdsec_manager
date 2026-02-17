import { createFileRoute } from "@tanstack/react-router";
import { IPManagementPage } from "@/features/ip-management/IPManagementPage";

export const Route = createFileRoute("/ip-management")({
  component: IPManagementPage,
});
