# CrowdSec Manager - React Frontend

A comprehensive React/TypeScript frontend application for managing CrowdSec security infrastructure with Shadcn UI.

## Features

- **Complete API Coverage**: All 43 backend API endpoints integrated
- **Type-Safe**: Full TypeScript support with strict mode
- **Modern UI**: Shadcn UI components with Tailwind CSS
- **Real-time Updates**: TanStack Query with auto-refetch
- **Responsive Design**: Mobile-first, works on all devices
- **Error Handling**: Toast notifications for user feedback
- **Loading States**: Proper loading indicators throughout
- **Confirmation Dialogs**: For all destructive actions

## Tech Stack

- **React 18** - UI library
- **TypeScript** - Type safety
- **Vite** - Build tool
- **React Router** - Client-side routing
- **TanStack Query** - Data fetching and caching
- **Axios** - HTTP client
- **Shadcn UI** - Component library
- **Tailwind CSS** - Styling
- **Lucide React** - Icons
- **Sonner** - Toast notifications

## Project Structure

```
web/
├── public/
│   └── index.html
├── src/
│   ├── components/
│   │   ├── ui/              # Shadcn UI components
│   │   │   ├── button.tsx
│   │   │   ├── card.tsx
│   │   │   ├── dialog.tsx
│   │   │   ├── input.tsx
│   │   │   ├── label.tsx
│   │   │   ├── select.tsx
│   │   │   ├── separator.tsx
│   │   │   ├── switch.tsx
│   │   │   ├── tabs.tsx
│   │   │   ├── table.tsx
│   │   │   ├── badge.tsx
│   │   │   ├── alert-dialog.tsx
│   │   │   └── tooltip.tsx
│   │   ├── Layout.tsx       # Main layout wrapper
│   │   ├── Sidebar.tsx      # Navigation sidebar
│   │   └── Header.tsx       # Top header
│   ├── lib/
│   │   ├── api.ts           # API client with all 43 endpoints
│   │   └── utils.ts         # Utility functions
│   ├── pages/
│   │   ├── Dashboard.tsx    # Overview dashboard
│   │   ├── Health.tsx       # Health & diagnostics
│   │   ├── IPManagement.tsx # IP management
│   │   ├── Whitelist.tsx    # Whitelist management
│   │   ├── Scenarios.tsx    # Scenario management
│   │   ├── Captcha.tsx      # Captcha configuration
│   │   ├── Logs.tsx         # Logs & monitoring
│   │   ├── Backup.tsx       # Backup management
│   │   ├── Update.tsx       # Stack updates
│   │   ├── Cron.tsx         # Cron job management
│   │   └── Services.tsx     # Service management
│   ├── App.tsx              # Main app component
│   ├── main.tsx             # Entry point
│   └── index.css            # Global styles
├── package.json
├── tsconfig.json
├── vite.config.ts
├── tailwind.config.js
└── components.json
```

## Installation

```bash
# Navigate to web directory
cd web

# Install dependencies
npm install
```

## Development

```bash
# Start development server (runs on http://localhost:3000)
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Run linter
npm run lint
```

## API Integration

The application connects to the backend API at `http://localhost:8080/api`. All 43 endpoints are mapped in `src/lib/api.ts`:

### Endpoint Categories

1. **Health & Diagnostics** (2 endpoints)
   - Check stack health
   - Complete diagnostics

2. **IP Management** (4 endpoints)
   - Get public IP
   - Check if IP is blocked
   - Check IP security
   - Unban IP

3. **Whitelist Management** (7 endpoints)
   - View whitelists
   - Whitelist current IP
   - Whitelist manual IP
   - Whitelist CIDR
   - Add to CrowdSec whitelist
   - Add to Traefik whitelist
   - Comprehensive whitelist setup

4. **Scenarios** (2 endpoints)
   - Setup custom scenarios
   - List scenarios

5. **Captcha** (2 endpoints)
   - Setup captcha
   - Get captcha status

6. **Logs** (5 endpoints)
   - Get CrowdSec logs
   - Get Traefik logs
   - Analyze Traefik logs
   - Get service logs
   - Stream logs (WebSocket)

7. **Backup** (6 endpoints)
   - List backups
   - Create backup
   - Restore backup
   - Delete backup
   - Cleanup old backups
   - Get latest backup

8. **Update** (3 endpoints)
   - Get current tags
   - Update with CrowdSec
   - Update without CrowdSec

9. **Cron** (3 endpoints)
   - Setup cron job
   - List cron jobs
   - Delete cron job

10. **Services** (3 endpoints)
    - Verify services
    - Graceful shutdown
    - Service actions (start/stop/restart)

11. **CrowdSec Specific** (4 endpoints)
    - Get bouncers
    - Get decisions
    - Get metrics
    - Enroll CrowdSec

12. **Traefik Specific** (2 endpoints)
    - Check integration
    - Get config

## Page Implementations

### Dashboard
- System status overview
- Container health cards
- Active decisions count
- Bouncers count
- Quick action links

### Health & Diagnostics
- Stack health display
- Complete diagnostics
- Bouncers list with status
- Metrics visualization
- Traefik integration check

### IP Management
- IP security checker
- Unban IP functionality
- Blocked IPs table
- Public IP display

### Whitelist Management
- Tabbed interface (CrowdSec/Traefik)
- View current whitelists
- Add IP/CIDR forms
- Comprehensive setup wizard

### Scenarios
- List installed scenarios
- Custom scenario setup
- Scenario details

### Captcha Configuration
- Provider selection
- Site key/secret key input
- Status indicator

### Logs & Monitoring
- Service selector dropdown
- Real-time log viewer
- WebSocket streaming
- Advanced log analysis
- Auto-refresh toggle

### Backup Management
- Backups table with details
- Create backup button
- Restore with confirmation
- Delete with confirmation
- Cleanup old backups

### Stack Update
- Current image tags display
- New tags input form
- Update with/without CrowdSec options
- Update progress indicator

### Cron Job Management
- Cron jobs table
- Add new job form
- Schedule picker
- Delete with confirmation

### Services Management
- Service status cards
- Start/stop/restart buttons
- Graceful shutdown option
- Real-time status updates

## Development Guidelines

### Adding a New Page

1. Create the page component in `src/pages/`
2. Add route in `src/App.tsx`
3. Add navigation item in `src/components/Sidebar.tsx`
4. Use TanStack Query for data fetching:

```typescript
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { yourAPI } from '@/lib/api'
import { toast } from 'sonner'

export default function YourPage() {
  const queryClient = useQueryClient()

  // Fetch data
  const { data, isLoading, error } = useQuery({
    queryKey: ['yourDataKey'],
    queryFn: () => yourAPI.getData(),
    refetchInterval: 30000, // Optional: auto-refetch
  })

  // Mutation
  const mutation = useMutation({
    mutationFn: yourAPI.updateData,
    onSuccess: () => {
      toast.success('Success!')
      queryClient.invalidateQueries({ queryKey: ['yourDataKey'] })
    },
    onError: (error) => {
      toast.error(`Error: ${error.message}`)
    },
  })

  // ... component implementation
}
```

### Using Shadcn Components

All Shadcn UI components are available in `src/components/ui/`. Import and use them:

```typescript
import { Button } from '@/components/ui/button'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

function MyComponent() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>My Card</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div>
            <Label htmlFor="name">Name</Label>
            <Input id="name" placeholder="Enter name" />
          </div>
          <Button>Submit</Button>
        </div>
      </CardContent>
    </Card>
  )
}
```

### Styling with Tailwind

Use Tailwind utility classes for styling:

```typescript
<div className="space-y-6">
  <h1 className="text-3xl font-bold">Title</h1>
  <p className="text-muted-foreground">Description</p>
  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
    {/* Grid items */}
  </div>
</div>
```

## Configuration

### Vite Proxy

The Vite dev server proxies `/api` requests to `http://localhost:8080`. Configure in `vite.config.ts`:

```typescript
server: {
  port: 3000,
  proxy: {
    '/api': {
      target: 'http://localhost:8080',
      changeOrigin: true,
    },
  },
}
```

### TypeScript

Strict mode enabled with path aliases:

```json
{
  "compilerOptions": {
    "strict": true,
    "paths": {
      "@/*": ["./src/*"]
    }
  }
}
```

## Troubleshooting

### Common Issues

1. **Port already in use**: Change port in `vite.config.ts`
2. **API not connecting**: Ensure backend is running on port 8080
3. **Type errors**: Run `npm install` to ensure all types are installed
4. **Styling issues**: Ensure Tailwind classes are recognized

### Debug Mode

Enable React Query DevTools:

```typescript
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'

// In your App component
<QueryClientProvider client={queryClient}>
  <App />
  <ReactQueryDevtools initialIsOpen={false} />
</QueryClientProvider>
```

## Production Deployment

```bash
# Build for production
npm run build

# Output in dist/ directory
# Serve with any static file server
```

## License

MIT

## Support

For issues or questions, refer to the main project documentation or the `IMPLEMENTATION_GUIDE.md` for detailed implementation examples.
