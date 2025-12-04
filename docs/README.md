# CrowdSec Manager Documentation

This directory contains the official documentation for **CrowdSec Manager**, built with [Next.js 16](https://nextjs.org/) and [Fumadocs](https://fumadocs.dev/).

##  Tech Stack

- **Framework**: Next.js 16 (App Router)
- **Documentation Engine**: Fumadocs (MDX-based)
- **Styling**: Tailwind CSS (aligned with main project theme)
- **Deployment**: Vercel

## Getting Started

### Prerequisites

- Node.js 18+
- npm

### Installation

Navigate to the `docs` directory and install dependencies:

```bash
cd docs
npm install
```

### Running Locally

Start the development server:

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to view the documentation.

##  Project Structure

```
docs/
├── content/docs/       # MDX documentation files
│   ├── features/       # Feature-specific docs
│   ├── configuration/  # Configuration guides
│   └── ...
├── src/
│   ├── app/            # Next.js App Router pages
│   └── ...
├── public/             # Static assets (images, etc.)
├── vercel.json         # Deployment configuration
└── ...
```

##  Writing Documentation

### Adding a New Page

1.  Create a new `.mdx` file in `content/docs/` or a subdirectory.
2.  Add the required frontmatter:

```mdx
---
title: Page Title
description: A brief description of the page content.
---

# Page Title

Content goes here...
```

### Ordering Pages

To control the order of pages in the sidebar, edit or create a `meta.json` file in the respective directory:

```json
{
  "pages": [
    "index",
    "quick-start",
    "features",
    "configuration"
  ]
}
```

### Components

We use standard Markdown syntax along with Fumadocs UI components. You can also use Tailwind CSS classes directly in your MDX files.

##  Deployment

The documentation is configured for deployment on **Vercel**.

- `vercel.json` handles the build configuration (`cleanUrls: true`).
- A custom `404` page is included in `src/app/not-found.tsx`.

To build locally:

```bash
npm run build
```
