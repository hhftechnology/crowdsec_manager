import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { ConfigPathRequest, ConfigPathResponse } from '@/lib/api'
import { ErrorContexts, getErrorMessage } from '@/lib/api/errors'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Settings, FileCode } from 'lucide-react'
import { PageHeader } from '@/components/common'

function EditableConfigForm({ initialPath, currentPath }: { initialPath: string; currentPath: string }) {
  const queryClient = useQueryClient()
  const [configPath, setConfigPath] = useState(initialPath)

  const updatePathMutation = useMutation({
    mutationFn: (data: ConfigPathRequest) => api.traefik.setConfigPath(data),
    onSuccess: () => {
      toast.success('Configuration path updated successfully')
      queryClient.invalidateQueries({ queryKey: ['traefik-config-path'] })
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, 'Failed to update configuration path', ErrorContexts.TraefikConfigPathUpdate))
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!configPath.trim()) {
      toast.error('Please enter a valid path')
      return
    }
    updatePathMutation.mutate({ dynamic_config_path: configPath })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="config-path">
          Dynamic Config Path <span className="text-destructive">*</span>
        </Label>
        <Input
          id="config-path"
          type="text"
          placeholder="/etc/traefik/dynamic_config.yml"
          value={configPath}
          onChange={(e) => setConfigPath(e.target.value)}
        />
        <p className="text-xs text-muted-foreground">
          The absolute path to the dynamic_config.yml file in the Traefik container
        </p>
      </div>

      <div className="p-4 bg-muted rounded-lg">
        <p className="text-sm font-semibold mb-2">Current Path:</p>
        <code className="text-sm font-mono">{currentPath || 'Not set'}</code>
      </div>

      <Button
        type="submit"
        className="w-full"
        disabled={updatePathMutation.isPending}
      >
        {updatePathMutation.isPending ? 'Updating...' : 'Update Configuration Path'}
      </Button>
    </form>
  )
}

export default function Configuration() {
  const { data: pathData, isLoading } = useQuery<ConfigPathResponse | null>({
    queryKey: ['traefik-config-path'],
    queryFn: async () => {
      const response = await api.traefik.getConfigPath()
      return response.data.data ?? null
    },
  })

  return (
    <div className="space-y-6">
      <PageHeader
        title="Configuration"
        description="Manage system configuration and file paths"
      />

      {/* Traefik Configuration Path */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileCode className="h-5 w-5" />
            Traefik Dynamic Configuration Path
          </CardTitle>
          <CardDescription>
            Configure the path to the Traefik dynamic_config.yml file
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="h-24 bg-muted animate-pulse rounded" />
          ) : (
            <EditableConfigForm
              key={pathData?.dynamic_config_path ?? ''}
              initialPath={pathData?.dynamic_config_path ?? ''}
              currentPath={pathData?.dynamic_config_path ?? ''}
            />
          )}
        </CardContent>
      </Card>

      {/* Configuration Info */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            Configuration Notes
          </CardTitle>
          <CardDescription>
            Important information about configuration management
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <p className="text-sm text-muted-foreground">
            The dynamic configuration path is used when:
          </p>
          <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
            <li>Checking Traefik-CrowdSec integration</li>
            <li>Adding IPs to the Traefik whitelist</li>
            <li>Verifying middleware configuration</li>
            <li>Updating captcha settings</li>
          </ul>
          <div className="pt-2">
            <p className="text-sm font-semibold text-foreground">Default Path:</p>
            <code className="text-sm font-mono">/etc/traefik/dynamic_config.yml</code>
          </div>
          <div className="pt-2">
            <p className="text-xs text-muted-foreground">
              If your Traefik configuration uses a different path or filename, update it here to ensure proper integration with CrowdSec Manager.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
