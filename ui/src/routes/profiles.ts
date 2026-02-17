import { createFileRoute } from "@tanstack/react-router";
import { ProfilesPage } from "@/features/profiles/ProfilesPage";

export const Route = createFileRoute("/profiles")({
  component: ProfilesPage,
});
