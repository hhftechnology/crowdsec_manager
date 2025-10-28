import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { UpdateRequest } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog'
import { RefreshCw, AlertTriangle, Info, Package } from 'lucide-react'

export default function Update() {
  const queryClient = useQueryClient()
  const [pangolinTag, setPangolinTag] = useState('')
  const [gerbilTag, setGerbilTag] = useState('')
  const [traefikTag, setTraefikTag] = useState('')
  const [crowdsecTag, setCrowdsecTag] = useState('')

  const { data: currentTags, isLoading } = useQuery({
    queryKey: ['current-tags'],
    queryFn: async () => {
      const response = await api.update.getCurrentTags()
      return response.data.data
    },
  })

  const updateWithCrowdSecMutation = useMutation({
    mutationFn: (data: UpdateRequest) => api.update.updateWithCrowdSec(data),
    onSuccess: () => {
      toast.success('Update with CrowdSec completed successfully')
      queryClient.invalidateQueries({ queryKey: ['current-tags'] })
      // Reset form
      setPangolinTag('')
      setGerbilTag('')
      setTraefikTag('')
      setCrowdsecTag('')
    },
    onError: () => {
      toast.error('Failed to update with CrowdSec')
    },
  })

  const updateWithoutCrowdSecMutation = useMutation({
    mutationFn: (data: UpdateRequest) => api.update.updateWithoutCrowdSec(data),
    onSuccess: () => {
      toast.success('Update without CrowdSec completed successfully')
      queryClient.invalidateQueries({ queryKey: ['current-tags'] })
      // Reset form
      setPangolinTag('')
      setGerbilTag('')
      setTraefikTag('')
    },
    onError: () => {
      toast.error('Failed to update without CrowdSec')
    },
  })

  const handleUpdateWithCrowdSec = () => {
    const updateData: UpdateRequest = {
      pangolin_tag: pangolinTag || undefined,
      gerbil_tag: gerbilTag || undefined,
      traefik_tag: traefikTag || undefined,
      crowdsec_tag: crowdsecTag || undefined,
      include_crowdsec: true,
    }

    updateWithCrowdSecMutation.mutate(updateData)
  }

  const handleUpdateWithoutCrowdSec = () => {
    const updateData: UpdateRequest = {
      pangolin_tag: pangolinTag || undefined,
      gerbil_tag: gerbilTag || undefined,
      traefik_tag: traefikTag || undefined,
      include_crowdsec: false,
    }

    updateWithoutCrowdSecMutation.mutate(updateData)
  }

  const isUpdating = updateWithCrowdSecMutation.isPending || updateWithoutCrowdSecMutation.isPending

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">System Update</h1>
        <p className="text-muted-foreground mt-2">
          Update Docker image tags for system components
        </p>
      </div>

      {/* Current Tags */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Package className="h-5 w-5" />
            Current Image Tags
          </CardTitle>
          <CardDescription>
            Currently deployed Docker image versions
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-2">
              <div className="h-16 bg-muted animate-pulse rounded" />
              <div className="h-16 bg-muted animate-pulse rounded" />
            </div>
          ) : currentTags ? (
            <div className="grid gap-4 md:grid-cols-2">
              <div className="p-4 border rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Pangolin</p>
                    <p className="font-mono text-sm mt-1">{currentTags.pangolin || 'N/A'}</p>
                  </div>
                  <Badge variant="secondary">Current</Badge>
                </div>
              </div>

              <div className="p-4 border rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Gerbil</p>
                    <p className="font-mono text-sm mt-1">{currentTags.gerbil || 'N/A'}</p>
                  </div>
                  <Badge variant="secondary">Current</Badge>
                </div>
              </div>

              <div className="p-4 border rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Traefik</p>
                    <p className="font-mono text-sm mt-1">{currentTags.traefik || 'N/A'}</p>
                  </div>
                  <Badge variant="secondary">Current</Badge>
                </div>
              </div>

              <div className="p-4 border rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">CrowdSec</p>
                    <p className="font-mono text-sm mt-1">{currentTags.crowdsec || 'N/A'}</p>
                  </div>
                  <Badge variant="secondary">Current</Badge>
                </div>
              </div>
            </div>
          ) : (
            <p className="text-center text-muted-foreground py-8">
              Unable to fetch current tags
            </p>
          )}
        </CardContent>
      </Card>

      {/* Update Form */}
      <Card>
        <CardHeader>
          <CardTitle>Update Image Tags</CardTitle>
          <CardDescription>
            Specify new Docker image tags (leave blank to keep current version)
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="pangolin-tag">Pangolin Tag</Label>
            <Input
              id="pangolin-tag"
              type="text"
              placeholder="e.g., latest, v1.0.0, stable"
              value={pangolinTag}
              onChange={(e) => setPangolinTag(e.target.value)}
              disabled={isUpdating}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="gerbil-tag">Gerbil Tag</Label>
            <Input
              id="gerbil-tag"
              type="text"
              placeholder="e.g., latest, v1.0.0, stable"
              value={gerbilTag}
              onChange={(e) => setGerbilTag(e.target.value)}
              disabled={isUpdating}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="traefik-tag">Traefik Tag</Label>
            <Input
              id="traefik-tag"
              type="text"
              placeholder="e.g., latest, v2.10, stable"
              value={traefikTag}
              onChange={(e) => setTraefikTag(e.target.value)}
              disabled={isUpdating}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="crowdsec-tag">CrowdSec Tag</Label>
            <Input
              id="crowdsec-tag"
              type="text"
              placeholder="e.g., latest, v1.5.0, stable"
              value={crowdsecTag}
              onChange={(e) => setCrowdsecTag(e.target.value)}
              disabled={isUpdating}
            />
            <p className="text-xs text-muted-foreground">
              Only used when updating with CrowdSec
            </p>
          </div>

          <div className="flex gap-2 pt-4">
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button
                  className="flex-1"
                  disabled={isUpdating}
                >
                  <RefreshCw className="mr-2 h-4 w-4" />
                  Update with CrowdSec
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle className="flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-orange-500" />
                    Update with CrowdSec?
                  </AlertDialogTitle>
                  <AlertDialogDescription className="space-y-2">
                    <p>
                      This will update all components including CrowdSec. The operation will:
                    </p>
                    <ul className="list-disc list-inside space-y-1 ml-4 text-sm">
                      <li>Create a backup before updating</li>
                      <li>Pull new Docker images</li>
                      <li>Restart all containers</li>
                      <li>Update CrowdSec configuration</li>
                    </ul>
                    <p className="text-orange-500 font-medium pt-2">
                      This may cause brief downtime. Continue?
                    </p>
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction
                    onClick={handleUpdateWithCrowdSec}
                    className="bg-orange-500 text-white hover:bg-orange-600"
                  >
                    Update System
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>

            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button
                  variant="outline"
                  className="flex-1"
                  disabled={isUpdating}
                >
                  <RefreshCw className="mr-2 h-4 w-4" />
                  Update without CrowdSec
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle className="flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-orange-500" />
                    Update without CrowdSec?
                  </AlertDialogTitle>
                  <AlertDialogDescription className="space-y-2">
                    <p>
                      This will update all components except CrowdSec. The operation will:
                    </p>
                    <ul className="list-disc list-inside space-y-1 ml-4 text-sm">
                      <li>Create a backup before updating</li>
                      <li>Pull new Docker images (excluding CrowdSec)</li>
                      <li>Restart affected containers</li>
                      <li>Keep CrowdSec at current version</li>
                    </ul>
                    <p className="text-orange-500 font-medium pt-2">
                      This may cause brief downtime. Continue?
                    </p>
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction
                    onClick={handleUpdateWithoutCrowdSec}
                    className="bg-orange-500 text-white hover:bg-orange-600"
                  >
                    Update System
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        </CardContent>
      </Card>

      {/* Information */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Info className="h-5 w-5" />
            Update Information
          </CardTitle>
          <CardDescription>
            Important notes about the update process
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          <div>
            <p className="font-medium text-foreground">Automatic Backup</p>
            <p>A backup is automatically created before any update operation.</p>
          </div>
          <div>
            <p className="font-medium text-foreground">Image Tags</p>
            <p>
              Common tags: <code className="text-xs bg-muted px-1 py-0.5 rounded">latest</code>,{' '}
              <code className="text-xs bg-muted px-1 py-0.5 rounded">stable</code>,{' '}
              <code className="text-xs bg-muted px-1 py-0.5 rounded">v1.0.0</code>. Check Docker Hub for available tags.
            </p>
          </div>
          <div>
            <p className="font-medium text-foreground">Update Strategy</p>
            <p>
              Use "Update with CrowdSec" for full system updates. Use "Update without CrowdSec" when
              you want to keep CrowdSec stable while updating other components.
            </p>
          </div>
          <div>
            <p className="font-medium text-foreground">Rollback</p>
            <p>
              If an update fails or causes issues, you can restore from the automatically created
              backup in the Backup Management page.
            </p>
          </div>
          <div className="flex items-start gap-2 p-3 bg-orange-500/10 border border-orange-500/20 rounded">
            <AlertTriangle className="h-4 w-4 mt-0.5 text-orange-500" />
            <div>
              <p className="font-medium text-foreground">Downtime Warning</p>
              <p>
                Updates require restarting containers, which will cause brief service interruptions.
                Plan updates during maintenance windows.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
