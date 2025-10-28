import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { ConfigPathRequest } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Settings, FileCode } from 'lucide-react'

export default function Configuration() {
  const queryClient = useQueryClient()
  const [configPath, setConfigPath] = useState('')

  const { data: pathData, isLoading } = useQuery({
    queryKey: ['traefik-config-path'],
    queryFn: async () => {
      const response = await api.traefik.getConfigPath()
      return response.data.data
    },
    onSuccess: (data: any) => {
      if (data?.dynamic_config_path) {
        setConfigPath(data.dynamic_config_path)
      }
    },
  })

  const updatePathMutation = useMutation({
    mutationFn: (data: ConfigPathRequest) => api.traefik.setConfigPath(data),
    onSuccess: () => {
      toast.success('Configuration path updated successfully')
      queryClient.invalidateQueries({ queryKey: ['traefik-config-path'] })
    },
    onError: () => {
      toast.error('Failed to update configuration path')
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
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Configuration</h1>
        <p className="text-muted-foreground mt-2">
          Manage system configuration and file paths
        </p>
      </div>

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
                <code className="text-sm font-mono">{pathData?.dynamic_config_path || 'Not set'}</code>
              </div>

              <Button
                type="submit"
                className="w-full"
                disabled={updatePathMutation.isPending}
              >
                {updatePathMutation.isPending ? 'Updating...' : 'Update Configuration Path'}
              </Button>
            </form>
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
