import {
  Activity,
  AlertTriangle,
  Archive,
  FileText,
  Globe,
  HardDrive,
  LayoutDashboard,
  ListChecks,
  Lock,
  type LucideIcon,
  MonitorCheck,
  ScrollText,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import { Link, useRouterState } from "@tanstack/react-router";

interface NavItem {
  label: string;
  href: string;
  icon: LucideIcon;
}

const navGroups: { label: string; items: NavItem[] }[] = [
  {
    label: "Overview",
    items: [
      { label: "Dashboard", href: "/", icon: LayoutDashboard },
      { label: "Health & Diagnostics", href: "/health", icon: Activity },
      { label: "Services", href: "/services", icon: HardDrive },
    ],
  },
  {
    label: "Security",
    items: [
      { label: "IP Management", href: "/ip-management", icon: Globe },
      { label: "Whitelist", href: "/whitelist", icon: ShieldCheck },
      { label: "Allowlist", href: "/allowlist", icon: UserCheck },
      { label: "Decisions", href: "/decisions", icon: ShieldAlert },
      { label: "Alerts", href: "/alerts", icon: AlertTriangle },
    ],
  },
  {
    label: "Configuration",
    items: [
      { label: "Scenarios", href: "/scenarios", icon: ListChecks },
      { label: "Profiles", href: "/profiles", icon: FileText },
      { label: "Captcha", href: "/captcha", icon: Lock },
      { label: "Notifications", href: "/notifications", icon: MonitorCheck },
    ],
  },
  {
    label: "Operations",
    items: [
      { label: "Logs & Monitoring", href: "/logs", icon: ScrollText },
      { label: "Backups", href: "/backups", icon: Archive },
      { label: "Configuration", href: "/configuration", icon: Settings },
    ],
  },
];

export function AppSidebar() {
  const routerState = useRouterState();
  const currentPath = routerState.location.pathname;

  return (
    <Sidebar>
      <SidebarHeader className="border-b border-sidebar-border px-4 py-3">
        <Link to="/" className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
            <Shield className="h-4.5 w-4.5 text-primary-foreground" />
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-semibold leading-tight text-sidebar-foreground">
              CrowdSec Manager
            </span>
            <span className="text-[10px] font-medium uppercase tracking-wider text-sidebar-muted">
              Observatory
            </span>
          </div>
        </Link>
      </SidebarHeader>

      <SidebarContent>
        {navGroups.map((group) => (
          <SidebarGroup key={group.label}>
            <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {group.items.map((item) => {
                  const isActive =
                    item.href === "/"
                      ? currentPath === "/"
                      : currentPath.startsWith(item.href);

                  return (
                    <SidebarMenuItem key={item.href}>
                      <SidebarMenuButton asChild isActive={isActive}>
                        <Link to={item.href}>
                          <item.icon className="h-4 w-4" />
                          <span>{item.label}</span>
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  );
                })}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
      </SidebarContent>

      <SidebarFooter className="border-t border-sidebar-border px-4 py-3">
        <p className="text-[10px] text-sidebar-muted">
          v0.1.0 &middot; Beta
        </p>
      </SidebarFooter>
    </Sidebar>
  );
}
