import Link from 'next/link';
import type { Metadata } from 'next';
import { getSiteUrl } from '@/lib/seo';
import pkg from 'package.json' with { type: 'json' };

const siteUrl = getSiteUrl();

export const metadata: Metadata = {
  title: 'Home',
  description:
    'CrowdSec Manager — web and mobile interface for CrowdSec operations, Traefik integration, decisions, alerts, and more.',
  alternates: {
    canonical: '/',
  },
  openGraph: {
    type: 'website',
    url: siteUrl,
    title: 'CrowdSec Manager',
    description:
      'Web and mobile interface for managing CrowdSec — decisions, alerts, scenarios, hub, logs, and backups.',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'CrowdSec Manager',
    description:
      'Web and mobile interface for managing CrowdSec — decisions, alerts, scenarios, hub, logs, and backups.',
  },
};

const pangolinCompose = `services:
  crowdsec-manager:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: crowdsec-manager
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - ENVIRONMENT=production
      - COMPOSE_FILE=/app/docker-compose.yml
      - CONFIG_DIR=/app/config
      - DATABASE_PATH=/app/data/settings.db
      - TRAEFIK_DYNAMIC_CONFIG=/etc/traefik/dynamic_config.yml
      - TRAEFIK_ACCESS_LOG=/var/log/traefik/access.log
      - BACKUP_DIR=/app/backups
      - INCLUDE_CROWDSEC=true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./config:/app/config
      - ./docker-compose.yml:/app/docker-compose.yml
      - ./backups:/app/backups
      - ./logs/app:/app/logs
      - ./data:/app/data
      - ./logs/traefik:/var/log/traefik:ro
    networks:
      - crowdsec-network
    depends_on:
      - crowdsec
      - traefik
  # traefik, pangolin, gerbil, crowdsec services...
networks:
  crowdsec-network:
    driver: bridge`;

const independentCompose = `services:
  crowdsec-manager:
    image: hhftechnology/crowdsec-manager:independent
    container_name: crowdsec-manager
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - ENVIRONMENT=production
      - CONFIG_DIR=/app/config
      - DATABASE_PATH=/app/data/settings.db
      - INCLUDE_CROWDSEC=true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./config:/app/config
      - ./logs/app:/app/logs
      - ./data:/app/data
    networks:
      - crowdsec-network
    depends_on:
      - crowdsec

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    environment:
      - COLLECTIONS=crowdsecurity/linux
    volumes:
      - crowdsec-db:/var/lib/crowdsec/data/
      - crowdsec-config:/etc/crowdsec/
    networks:
      - crowdsec-network

networks:
  crowdsec-network:
    driver: bridge

volumes:
  crowdsec-db:
  crowdsec-config:`;

export default function HomePage() {
  return (
    <main className="flex flex-1 flex-col">
      {/* Hero */}
      <section className="border-b border-border/60 bg-gradient-to-b from-muted/40 to-background">
        <div className="container mx-auto px-4 py-16 text-center lg:py-20">
          <p className="mb-3 text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground">
            Stable · v{pkg.version}
          </p>
          <h1 className="mb-4 text-4xl font-extrabold tracking-tight text-foreground lg:text-6xl">
            CrowdSec Manager
          </h1>
          <p className="mx-auto mb-8 max-w-2xl text-base text-muted-foreground lg:text-lg">
            Web and mobile interface for managing CrowdSec — decisions, alerts, scenarios, hub,
            logs, backups, and Traefik integration.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/docs/installation"
              className="rounded-md bg-primary px-6 py-3 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90"
            >
              Get Started
            </Link>
            <Link
              href="/docs/quick-start"
              className="rounded-md border border-input bg-background px-6 py-3 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground"
            >
              Quick Start
            </Link>
            <a
              href="https://github.com/hhftechnology/crowdsec_manager"
              target="_blank"
              rel="noreferrer"
              className="rounded-md border border-input bg-background px-6 py-3 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground"
            >
              GitHub
            </a>
            <a
              href="https://discord.gg/HDCt9MjyMJ"
              target="_blank"
              rel="noreferrer"
              className="rounded-md border border-input bg-background px-6 py-3 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground"
            >
              Discord
            </a>
          </div>
        </div>
      </section>

      {/* Mobile App */}
      <section className="border-b border-border/60 bg-muted/20">
        <div className="container mx-auto px-4 py-10 text-center">
          <h2 className="mb-2 text-xl font-semibold tracking-tight">Mobile App</h2>
          <p className="mb-6 text-sm text-muted-foreground">
            Native iOS and Android app — Pangolin and Basis connection modes supported.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-4">
            <a href="https://apps.apple.com/us/app/#" target="_blank" rel="noreferrer">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                width={135}
                height={39}
                alt="Download on the App Store"
                src="https://github.com/user-attachments/assets/45e31a11-cf6b-40a2-a083-6dc8d1f01291"
              />
            </a>
            <a
              href="https://play.google.com/store/apps/details?id=com.crowdsec.manager.mobile"
              target="_blank"
              rel="noreferrer"
            >
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                width={135}
                height={39}
                alt="Get it on Google Play"
                src="https://github.com/user-attachments/assets/acbba639-858f-4c74-85c7-92a4096efbf5"
              />
            </a>
            <a
              href="https://play.google.com/store/apps/details?id=com.crowdsec.manager.independent"
              target="_blank"
              rel="noreferrer"
            >
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                width={135}
                height={39}
                alt="Get it on Google Play (Independent)"
                src="https://github.com/user-attachments/assets/acbba639-858f-4c74-85c7-92a4096efbf5"
              />
            </a>
          </div>
          <div className="mt-4">
            <Link href="/docs/mobile-app" className="text-sm text-primary hover:underline">
              Mobile app setup guide →
            </Link>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="container mx-auto grid gap-4 px-4 py-10 md:grid-cols-2 lg:grid-cols-4">
        {[
          { title: 'Dashboard', desc: 'Health, alerts, metrics, and blocked IP activity at a glance' },
          { title: 'Decisions & Alerts', desc: 'Full analysis, history, repeated offenders, and bulk reapply' },
          { title: 'Hub & Scenarios', desc: 'Install, remove, and configure CrowdSec hub items and custom scenarios' },
          { title: 'Logs & Backups', desc: 'Live log streaming, Traefik analysis, config validation, and backup management' },
        ].map((item) => (
          <div key={item.title} className="rounded-lg border bg-card p-4 text-card-foreground">
            <p className="mb-1 text-sm font-semibold">{item.title}</p>
            <p className="text-xs text-muted-foreground">{item.desc}</p>
          </div>
        ))}
      </section>

      {/* Deployment variants */}
      <section className="container mx-auto px-4 pb-16">
        <h2 className="mb-6 text-xl font-semibold tracking-tight">Deployment Variants</h2>
        <div className="grid gap-6 lg:grid-cols-2">
          <div>
            <div className="mb-3 flex items-center justify-between gap-4">
              <div>
                <span className="text-sm font-semibold">Pangolin</span>
                <span className="ml-2 rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                  full stack
                </span>
              </div>
              <Link className="text-xs text-primary hover:underline" href="/docs/installation">
                Full guide →
              </Link>
            </div>
            <p className="mb-3 text-xs text-muted-foreground">
              Traefik + Pangolin + Gerbil + CrowdSec. Builds from source. Includes backup
              management and Traefik integration.
            </p>
            <pre className="overflow-x-auto rounded-lg border bg-muted/40 p-4 text-xs">
              <code>{pangolinCompose}</code>
            </pre>
          </div>

          <div>
            <div className="mb-3 flex items-center justify-between gap-4">
              <div>
                <span className="text-sm font-semibold">Independent</span>
                <span className="ml-2 rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                  standalone
                </span>
              </div>
              <Link className="text-xs text-primary hover:underline" href="/docs/installation">
                Full guide →
              </Link>
            </div>
            <p className="mb-3 text-xs text-muted-foreground">
              CrowdSec + manager only. Pre-built image. No Traefik, no Pangolin. Bring your own
              reverse proxy.
            </p>
            <pre className="overflow-x-auto rounded-lg border bg-muted/40 p-4 text-xs">
              <code>{independentCompose}</code>
            </pre>
          </div>
        </div>
      </section>
    </main>
  );
}
