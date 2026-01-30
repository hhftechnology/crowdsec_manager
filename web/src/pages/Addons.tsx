import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  Puzzle,
  Shield,
  Network,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
} from 'lucide-react'
import api from '@/lib/api'
import { useProxy } from '@/contexts/ProxyContext'

interface AddonStatus {
  name: string
  enabled: boolean
  running: boolean
  container_name: string
  version: string
  health: string
}

interface AddonInfo {
  name: string
  display_name: string
  description: string
  proxy_types: string[]
  required: boolean
  category: string
  status: AddonStatus
  features: string[]
}

interface AddonsResponse {
  proxy_type: string
  available_addons: AddonInfo[]
  total_addons: number
  supported_addons: number
}

export default function Addons() {
  const queryClient = useQueryClient()
  const { proxyType, proxyStatus, isLoading: proxyLoading } = useProxy()
  const [enablingAddon, setEnablingAddon] = useState<string | null>(null)

  const { data: addonsData, isLoading, error, refetch } = useQuery({
    queryKey: ['addons'],
    queryFn: async () => {
      const response = await api.get<{ success: boolean; data: AddonsResponse }>('/addons')
      return response.data.data
    },
    enabled: !proxyLoading,
  })

  const enableMutation = useMutation({
    mutationFn: async (addonName: string) => {
      return api.post(`/addons/${addonName}/enable`)
    },
    onSuccess: (_, addonName) => {
      toast.success(`${addonName} addon enabled successfully`)
      queryClient.invalidateQueries({ queryKey: ['addons'] })
      setEnablingAddon(null)
    },
    onError: (error: Error, addonName) => {
      toast.error(`Failed to enable ${addonName}: ${error.message}`)
      setEnablingAddon(null)
    },
  })

  const disableMutation = useMutation({
    mutationFn: async (addonName: string) => {
      return api.post(`/addons/${addonName}/disable`)
    },
    onSuccess: (_, addonName) => {
      toast.success(`${addonName} addon disabled successfully`)
      queryClient.invalidateQueries({ queryKey: ['addons'] })
      setEnablingAddon(null)
    },
    onError: (error: Error, addonName) => {
      toast.error(`Failed to disable ${addonName}: ${error.message}`)
      setEnablingAddon(null)
    },
  })

  const handleToggleAddon = (addon: AddonInfo) => {
    setEnablingAddon(addon.name)
    if (addon.status.enabled) {
      disableMutation.mutate(addon.name)
    } else {
      enableMutation.mutate(addon.name)
    }
  }

  const getStatusIcon = (status: AddonStatus) => {
    if (!status.enabled) {
      return <XCircle className="h-5 w-5 text-muted-foreground" />
    }
    if (status.running) {
      return <CheckCircle className="h-5 w-5 text-green-500" />
    }
    return <AlertTriangle className="h-5 w-5 text-yellow-500" />
  }

  const getStatusBadge = (status: AddonStatus) => {
    if (!status.enabled) {
      return <Badge variant="secondary">Disabled</Badge>
    }
    if (status.running) {
      return <Badge variant="default" className="bg-green-500">Running</Badge>
    }
    return <Badge variant="destructive">Stopped</Badge>
  }

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'security':
        return <Shield className="h-8 w-8 text-primary" />
      case 'networking':
        return <Network className="h-8 w-8 text-primary" />
      default:
        return <Puzzle className="h-8 w-8 text-primary" />
    }
  }

  const resolvedProxyType = proxyStatus?.type || proxyType || 'unknown'

  // Show warning if not using Traefik
  if (!proxyLoading && resolvedProxyType !== 'traefik') {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Addons</h1>
          <p className="text-muted-foreground">
            Extend your proxy with additional features
          </p>
        </div>

        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            Addons are currently only available for Traefik proxy deployments.
            Your current proxy type is: <strong>{resolvedProxyType}</strong>
          </AlertDescription>
        </Alert>
      </div>
    )
  }

  if (isLoading || proxyLoading) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Addons</h1>
          <p className="text-muted-foreground">
            Extend your proxy with additional features
          </p>
        </div>

        <div className="grid gap-6 md:grid-cols-2">
          {[1, 2].map((i) => (
            <Card key={i}>
              <CardHeader>
                <Skeleton className="h-8 w-8" />
                <Skeleton className="h-6 w-32 mt-2" />
                <Skeleton className="h-4 w-full mt-2" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-3/4 mt-2" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Addons</h1>
          <p className="text-muted-foreground">
            Extend your proxy with additional features
          </p>
        </div>

        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            Failed to load addons. Please try again.
          </AlertDescription>
        </Alert>

        <Button onClick={() => refetch()} variant="outline">
          <RefreshCw className="mr-2 h-4 w-4" />
          Retry
        </Button>
      </div>
    )
  }

  const addons = addonsData?.available_addons || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Addons</h1>
          <p className="text-muted-foreground">
            Extend your {addonsData?.proxy_type || resolvedProxyType || 'proxy'} with additional
            features
          </p>
        </div>
        <Button onClick={() => refetch()} variant="outline" size="sm">
          <RefreshCw className="mr-2 h-4 w-4" />
          Refresh
        </Button>
      </div>

      {addons.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Puzzle className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium">No Addons Available</h3>
            <p className="text-sm text-muted-foreground mt-2">
              No addons are available for your current proxy configuration.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-6 md:grid-cols-2">
          {addons.map((addon) => (
            <Card key={addon.name} className="relative">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-4">
                    {getCategoryIcon(addon.category)}
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        {addon.display_name}
                        {getStatusBadge(addon.status)}
                      </CardTitle>
                      <CardDescription className="mt-1">
                        {addon.description}
                      </CardDescription>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {getStatusIcon(addon.status)}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Features List */}
                <div>
                  <h4 className="text-sm font-medium mb-2">Features</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    {addon.features.map((feature, idx) => (
                      <li key={idx} className="flex items-center gap-2">
                        <CheckCircle className="h-3 w-3 text-green-500" />
                        {feature}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Status Details */}
                {addon.status.enabled && (
                  <div className="text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Container:</span>
                      <span className="font-mono">{addon.status.container_name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Version:</span>
                      <span>{addon.status.version}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Health:</span>
                      <span className={
                        addon.status.health === 'healthy' ? 'text-green-500' :
                        addon.status.health === 'unhealthy' ? 'text-red-500' :
                        'text-muted-foreground'
                      }>
                        {addon.status.health}
                      </span>
                    </div>
                  </div>
                )}

                {/* Toggle & Actions */}
                <div className="flex items-center justify-between pt-4 border-t">
                  <div className="flex items-center gap-2">
                    <Switch
                      checked={addon.status.enabled}
                      onCheckedChange={() => handleToggleAddon(addon)}
                      disabled={enablingAddon === addon.name}
                    />
                    <span className="text-sm">
                      {addon.status.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </div>
                  {addon.name === 'pangolin' && (
                    <Button variant="outline" size="sm" asChild>
                      <a
                        href="https://github.com/fosrl/pangolin"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        <ExternalLink className="mr-2 h-3 w-3" />
                        Docs
                      </a>
                    </Button>
                  )}
                  {addon.name === 'gerbil' && (
                    <Button variant="outline" size="sm" asChild>
                      <a
                        href="https://github.com/fosrl/gerbil"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        <ExternalLink className="mr-2 h-3 w-3" />
                        Docs
                      </a>
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Information Card */}
      <Card className="border-dashed">
        <CardHeader>
          <CardTitle className="text-lg">About Addons</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>
            Addons extend the functionality of your Traefik proxy with additional
            security and networking capabilities.
          </p>
          <p>
            <strong>Pangolin:</strong> Advanced SSL/TLS certificate management and
            security middleware for Traefik.
          </p>
          <p>
            <strong>Gerbil:</strong> WireGuard VPN integration for secure remote
            access and network security policies.
          </p>
          <p className="text-xs mt-4">
            Note: Enabling or disabling addons may require restarting Docker
            Compose services to take effect.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
