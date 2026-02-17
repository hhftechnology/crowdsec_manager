import { Outlet } from "@tanstack/react-router";
import { AppShell } from "./AppShell";

export function RootLayout() {
  return (
    <AppShell>
      <Outlet />
    </AppShell>
  );
}
