import { useNavigate } from 'react-router-dom';
import { PageHeader } from '@/components/PageHeader';
import { ListChecks, FileCode2, PackageOpen, TerminalSquare, Box } from 'lucide-react';
import { cn } from '@/lib/utils';

const sections = [
  {
    path: '/management/allowlists',
    icon: ListChecks,
    label: 'Allowlists',
    desc: 'List/create/inspect/add/remove/delete',
  },
  {
    path: '/management/scenarios',
    icon: FileCode2,
    label: 'Scenarios',
    desc: 'Setup/list/files/delete',
  },
  {
    path: '/management/hub',
    icon: PackageOpen,
    label: 'Hub',
    desc: 'Install/remove/manual apply/preferences/history',
  },
  {
    path: '/management/containers',
    icon: Box,
    label: 'Containers',
    desc: 'Start, stop, and restart Docker containers',
  },
  {
    path: '/management/terminal',
    icon: TerminalSquare,
    label: 'Terminal',
    desc: 'Interactive container shell',
  },
];

export default function ManagementPage() {
  const navigate = useNavigate();

  return (
    <div className="pb-nav">
      <PageHeader title="Management" subtitle="Endpoint-focused control panels" />
      <div className="px-4 grid grid-cols-1 gap-3">
        {sections.map((section, index) => (
          <button
            key={section.path}
            onClick={() => navigate(section.path)}
            className={cn(
              'rounded-xl border border-border bg-card p-4 text-left transition-all active:scale-[0.98] animate-fade-in',
            )}
            style={{ animationDelay: `${index * 40}ms` }}
          >
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                <section.icon className="h-5 w-5 text-primary" />
              </div>
              <div>
                <div className="text-sm font-semibold">{section.label}</div>
                <div className="text-xs text-muted-foreground">{section.desc}</div>
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
