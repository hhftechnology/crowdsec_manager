const fallbackSiteUrl = 'https://crowdsec-manager-docs.vercel.app';

export function getSiteUrl(): string {
  const envUrl = process.env.NEXT_PUBLIC_SITE_URL ?? process.env.SITE_URL;
  if (!envUrl) return fallbackSiteUrl;

  const withProtocol = envUrl.startsWith('http') ? envUrl : `https://${envUrl}`;
  return withProtocol.replace(/\/+$/, '');
}

export const siteMetadata = {
  name: 'CrowdSec Manager Docs',
  title: 'CrowdSec Manager Documentation',
  description:
    'Official documentation for CrowdSec Manager: installation, configuration, API, and operational guides.',
  keywords: [
    'CrowdSec Manager',
    'CrowdSec',
    'Pangolin',
    'Traefik',
    'security dashboard',
    'CrowdSec documentation',
  ],
};
