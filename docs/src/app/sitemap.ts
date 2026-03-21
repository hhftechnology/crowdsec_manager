import type { MetadataRoute } from 'next';
import { source } from '@/lib/source';
import { getSiteUrl } from '@/lib/seo';

export default function sitemap(): MetadataRoute.Sitemap {
  const siteUrl = getSiteUrl();
  const now = new Date();

  const staticRoutes: MetadataRoute.Sitemap = [
    {
      url: siteUrl,
      lastModified: now,
      changeFrequency: 'weekly',
      priority: 1,
    },
    {
      url: `${siteUrl}/docs`,
      lastModified: now,
      changeFrequency: 'daily',
      priority: 0.9,
    },
  ];

  const docRoutes: MetadataRoute.Sitemap = source
    .getPages()
    .filter((page) => page.slugs.length > 0)
    .map((page) => ({
      url: `${siteUrl}/docs/${page.slugs.join('/')}`,
      lastModified: now,
      changeFrequency: 'weekly',
      priority: page.slugs.length === 1 ? 0.85 : 0.75,
    }));

  return [...staticRoutes, ...docRoutes];
}
