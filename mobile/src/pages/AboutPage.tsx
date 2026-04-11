import { useState } from 'react';
import { Shield, Globe, Github, MessageCircle, Users, ExternalLink, ChevronLeft } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useMountEffect } from '@/hooks/useMountEffect';
import { App as CapApp } from '@capacitor/app';
import { PageHeader } from '@/components/PageHeader';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';

const links = [
  { label: 'Website', href: 'https://hhf.technology', icon: Globe },
  { label: 'GitHub', href: 'https://github.com/HHFTechnology', icon: Github },
  { label: 'Discord', href: 'https://discord.gg/HDCt9MjyMJ', icon: MessageCircle },
  { label: 'Forum', href: 'https://forum.hhf.technology', icon: Users },
];

const socialLinks = [
  { label: 'X / Twitter', href: 'https://x.com/hhftechnology' },
  { label: 'Reddit', href: 'https://reddit.com/u/hhftechnology' },
  { label: 'Instagram', href: 'https://instagram.com/hhftechnology' },
];

export default function AboutPage() {
  const navigate = useNavigate();
  const [appInfo, setAppInfo] = useState({ version: '1.0.0', build: '1' });

  useMountEffect(() => {
    CapApp.getInfo()
      .then((info) => setAppInfo({ version: info.version, build: info.build }))
      .catch(() => { /* PWA fallback — keep defaults */ });
  });

  return (
    <div className="pb-nav">
      <PageHeader
        title="About"
        action={
          <Button variant="ghost" size="sm" onClick={() => navigate(-1)} className="gap-1">
            <ChevronLeft className="h-4 w-4" />
            Back
          </Button>
        }
      />

      <div className="px-4 space-y-4">
        {/* App branding */}
        <section className="rounded-xl border border-border bg-card p-6 flex flex-col items-center text-center">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl gradient-maroon mb-4 shadow-lg">
            <Shield className="h-8 w-8 text-white" />
          </div>
          <h2 className="text-xl font-bold">CrowdSec Manager</h2>
          <p className="text-sm text-muted-foreground mt-1">Version {appInfo.version} (Build {appInfo.build})</p>
          <p className="text-xs text-muted-foreground mt-0.5">Capacitor 7 &middot; React 18</p>
          <p className="text-xs text-muted-foreground mt-0.5">Independent &middot; General Proxy</p>
        </section>

        {/* About HHF Technology */}
        <section className="rounded-xl border border-border bg-card p-4 space-y-3">
          <h3 className="text-sm font-semibold">HHF Technology</h3>
          <p className="text-sm text-muted-foreground leading-relaxed">
            Infrastructure Engineer &amp; Homelab Enthusiast — building containerized applications,
            managing virtual infrastructure, securing networks, and automating solutions.
          </p>
          <div className="flex flex-wrap gap-1.5">
            {['Kubernetes', 'Proxmox', 'OPNsense', 'TrueNAS', 'Docker'].map((tag) => (
              <span
                key={tag}
                className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-secondary text-secondary-foreground"
              >
                {tag}
              </span>
            ))}
          </div>
        </section>

        {/* Links */}
        <section className="rounded-xl border border-border bg-card overflow-hidden">
          <h3 className="text-sm font-semibold px-4 pt-4 pb-2">Links</h3>
          {links.map((link, i) => (
            <div key={link.href}>
              {i > 0 && <Separator />}
              <a
                href={link.href}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-3 px-4 py-3 hover:bg-secondary/50 transition-colors"
              >
                <link.icon className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm flex-1">{link.label}</span>
                <ExternalLink className="h-3.5 w-3.5 text-muted-foreground" />
              </a>
            </div>
          ))}
        </section>

        {/* Social */}
        <section className="rounded-xl border border-border bg-card overflow-hidden">
          <h3 className="text-sm font-semibold px-4 pt-4 pb-2">Social</h3>
          {socialLinks.map((link, i) => (
            <div key={link.href}>
              {i > 0 && <Separator />}
              <a
                href={link.href}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-3 px-4 py-3 hover:bg-secondary/50 transition-colors"
              >
                <span className="text-sm flex-1">{link.label}</span>
                <ExternalLink className="h-3.5 w-3.5 text-muted-foreground" />
              </a>
            </div>
          ))}
        </section>

        {/* Reset onboarding */}
        <section className="rounded-xl border border-border bg-card p-4">
          <Button
            variant="ghost"
            className="w-full text-sm text-muted-foreground"
            onClick={() => {
              localStorage.removeItem('csm_onboarding_complete');
              navigate('/');
              window.location.reload();
            }}
          >
            Replay Onboarding Walkthrough
          </Button>
        </section>
      </div>
    </div>
  );
}
