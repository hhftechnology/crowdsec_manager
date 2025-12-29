import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { WhitelistRequest } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Shield, Globe, Plus } from 'lucide-react'
import { useRunningContainers, useProxyType, useFeature } from '@/contexts/DeploymentContext'
import { ContainerRole } from '@/lib/deployment-types'

export default function Whitelist() {
  const queryClient = useQueryClient()
  const [manualIP, setManualIP] = useState('')
  const [cidr, setCidr] = useState('')
  const [addToCrowdSec, setAddToCrowdSec] = useState(true)
  const [addToTraefik, setAddToTraefik] = useState(true)

  // Get deployment information
  const runningContainers = useRunningContainers()
  const proxyType = useProxyType()
  const hasProxyWhitelist = useFeature('whitelistProxy')
  
  // Determine which containers support whitelisting
  const hasCrowdSec = runningContainers.some(c => 
    c.role === ContainerRole.SECURITY && c.name.toLowerCase().includes('crowdsec')
  )
  const hasTraefik = runningContainers.some(c => 
    c.role === ContainerRole.PROXY && c.name.toLowerCase().includes('traefik')
  )
  const hasOtherProxy = runningContainers.some(c => 
    c.role === ContainerRole.PROXY && 
    !c.name.toLowerCase().includes('traefik') &&
    c.capabilities.includes('whitelist')
  )
  
  // Determine proxy name for display
  const getProxyDisplayName = () => {
    if (hasTraefik) return 'Traefik'
    if (hasOtherProxy) {
      const proxyContainer = runningContainers.find(c => 
        c.role === ContainerRole.PROXY && 
        !c.name.toLowerCase().includes('traefik') &&
        c.capabilities.includes('whitelist')
      )
      if (proxyContainer) {
        const name = proxyContainer.name.toLowerCase()
        if (name.includes('nginx')) return 'Nginx'
        if (name.includes('caddy')) return 'Caddy'
        if (name.includes('haproxy')) return 'HAProxy'
        if (name.includes('zoraxy')) return 'Zoraxy'
        return 'Proxy'
      }
    }
    return 'Proxy'
  }
  
  const proxyDisplayName = getProxyDisplayName()
  const showProxyOptions = hasTraefik || hasOtherProxy

  const { data: whitelistData, isLoading } = useQuery({
    queryKey: ['whitelist'],
    queryFn: async () => {
      const response = await api.whitelist.view()
      return response.data.data
    },
  })

  const { data: publicIPData } = useQuery({
    queryKey: ['publicIP'],
    queryFn: async () => {
      const response = await api.ip.getPublicIP()
      return response.data.data
    },
  })

  const whitelistCurrentMutation = useMutation({
    mutationFn: () => api.whitelist.whitelistCurrent(),
    onSuccess: () => {
      toast.success('Current IP whitelisted successfully')
      queryClient.invalidateQueries({ queryKey: ['whitelist'] })
    },
    onError: () => {
      toast.error('Failed to whitelist current IP')
    },
  })

  const whitelistManualMutation = useMutation({
    mutationFn: (data: WhitelistRequest) => api.whitelist.whitelistManual(data),
    onSuccess: () => {
      toast.success('IP whitelisted successfully')
      setManualIP('')
      queryClient.invalidateQueries({ queryKey: ['whitelist'] })
    },
    onError: () => {
      toast.error('Failed to whitelist IP')
    },
  })

  const whitelistCIDRMutation = useMutation({
    mutationFn: (data: WhitelistRequest) => api.whitelist.whitelistCIDR(data),
    onSuccess: () => {
      toast.success('CIDR range whitelisted successfully')
      setCidr('')
      queryClient.invalidateQueries({ queryKey: ['whitelist'] })
    },
    onError: () => {
      toast.error('Failed to whitelist CIDR range')
    },
  })

  const comprehensiveMutation = useMutation({
    mutationFn: (data: WhitelistRequest) => api.whitelist.setupComprehensive(data),
    onSuccess: () => {
      toast.success('Comprehensive whitelist setup completed')
      queryClient.invalidateQueries({ queryKey: ['whitelist'] })
    },
    onError: () => {
      toast.error('Failed to setup comprehensive whitelist')
    },
  })

  const handleWhitelistCurrent = () => {
    whitelistCurrentMutation.mutate()
  }

  const handleWhitelistManual = (e: React.FormEvent) => {
    e.preventDefault()
    if (!manualIP.trim()) {
      toast.error('Please enter an IP address')
      return
    }
    whitelistManualMutation.mutate({
      ip: manualIP,
      add_to_crowdsec: addToCrowdSec,
      add_to_traefik: showProxyOptions ? addToTraefik : false,
    })
  }

  const handleWhitelistCIDR = (e: React.FormEvent) => {
    e.preventDefault()
    if (!cidr.trim()) {
      toast.error('Please enter a CIDR range')
      return
    }
    whitelistCIDRMutation.mutate({
      ip: '',
      cidr: cidr,
      add_to_crowdsec: addToCrowdSec,
      add_to_traefik: showProxyOptions ? addToTraefik : false,
    })
  }

  const handleComprehensive = () => {
    if (!publicIPData?.ip) {
      toast.error('Unable to get public IP')
      return
    }
    comprehensiveMutation.mutate({
      ip: publicIPData.ip,
      add_to_crowdsec: true,
      add_to_traefik: showProxyOptions,
      comprehensive: true,
    })
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Whitelist Management</h1>
        <p className="text-muted-foreground mt-2">
          {showProxyOptions 
            ? `Manage whitelisted IPs and CIDR ranges across CrowdSec and ${proxyDisplayName}`
            : 'Manage whitelisted IPs and CIDR ranges for CrowdSec'
          }
        </p>
      </div>

      {/* Current IP Quick Whitelist */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Whitelist</CardTitle>
          <CardDescription>
            Whitelist your current IP address with one click
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between p-4 border rounded-lg">
            <div>
              <p className="font-medium">Your Current IP</p>
              <p className="text-sm text-muted-foreground font-mono">
                {publicIPData?.ip || 'Loading...'}
              </p>
            </div>
            <Button
              onClick={handleWhitelistCurrent}
              disabled={whitelistCurrentMutation.isPending || !publicIPData?.ip}
            >
              <Shield className="mr-2 h-4 w-4" />
              Whitelist Current IP
            </Button>
          </div>

          <div className="border-t pt-4">
            <Button
              onClick={handleComprehensive}
              disabled={comprehensiveMutation.isPending || !publicIPData?.ip}
              variant="outline"
              className="w-full"
            >
              <Plus className="mr-2 h-4 w-4" />
              Setup Comprehensive Whitelist
            </Button>
            <p className="text-xs text-muted-foreground mt-2 text-center">
              {showProxyOptions 
                ? `Adds your IP to all whitelist locations (CrowdSec + ${proxyDisplayName})`
                : 'Adds your IP to CrowdSec whitelist'
              }
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Add IP/CIDR Forms */}
      <Tabs defaultValue="manual" className="space-y-4">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="manual">Manual IP</TabsTrigger>
          <TabsTrigger value="cidr">CIDR Range</TabsTrigger>
        </TabsList>

        <TabsContent value="manual">
          <Card>
            <CardHeader>
              <CardTitle>Whitelist Manual IP</CardTitle>
              <CardDescription>
                Add a specific IP address to the whitelist
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleWhitelistManual} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="manual-ip">IP Address</Label>
                  <Input
                    id="manual-ip"
                    type="text"
                    placeholder="192.168.1.100"
                    value={manualIP}
                    onChange={(e) => setManualIP(e.target.value)}
                  />
                </div>

                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label>Add to CrowdSec</Label>
                      <p className="text-sm text-muted-foreground">
                        Add to CrowdSec whitelist
                      </p>
                    </div>
                    <Switch
                      checked={addToCrowdSec}
                      onCheckedChange={setAddToCrowdSec}
                    />
                  </div>

                  {showProxyOptions && (
                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5">
                        <Label>Add to {proxyDisplayName}</Label>
                        <p className="text-sm text-muted-foreground">
                          Add to {proxyDisplayName} whitelist
                        </p>
                      </div>
                      <Switch
                        checked={addToTraefik}
                        onCheckedChange={setAddToTraefik}
                      />
                    </div>
                  )}
                </div>

                <Button
                  type="submit"
                  className="w-full"
                  disabled={whitelistManualMutation.isPending}
                >
                  {whitelistManualMutation.isPending ? 'Adding...' : 'Add IP to Whitelist'}
                </Button>
              </form>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="cidr">
          <Card>
            <CardHeader>
              <CardTitle>Whitelist CIDR Range</CardTitle>
              <CardDescription>
                Add a CIDR range to the whitelist
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleWhitelistCIDR} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="cidr">CIDR Range</Label>
                  <Input
                    id="cidr"
                    type="text"
                    placeholder="192.168.1.0/24"
                    value={cidr}
                    onChange={(e) => setCidr(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    Example: 192.168.1.0/24 or 10.0.0.0/8
                  </p>
                </div>

                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label>Add to CrowdSec</Label>
                      <p className="text-sm text-muted-foreground">
                        Add to CrowdSec whitelist
                      </p>
                    </div>
                    <Switch
                      checked={addToCrowdSec}
                      onCheckedChange={setAddToCrowdSec}
                    />
                  </div>

                  {showProxyOptions && (
                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5">
                        <Label>Add to {proxyDisplayName}</Label>
                        <p className="text-sm text-muted-foreground">
                          Add to {proxyDisplayName} whitelist
                        </p>
                      </div>
                      <Switch
                        checked={addToTraefik}
                        onCheckedChange={setAddToTraefik}
                      />
                    </div>
                  )}
                </div>

                <Button
                  type="submit"
                  className="w-full"
                  disabled={whitelistCIDRMutation.isPending}
                >
                  {whitelistCIDRMutation.isPending ? 'Adding...' : 'Add CIDR to Whitelist'}
                </Button>
              </form>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Current Whitelists */}
      <Card>
        <CardHeader>
          <CardTitle>Current Whitelists</CardTitle>
          <CardDescription>
            View all whitelisted IPs across services
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-2">
              <div className="h-24 bg-muted animate-pulse rounded" />
              <div className="h-24 bg-muted animate-pulse rounded" />
            </div>
          ) : (
            <div className="space-y-4">
              {/* CrowdSec Whitelist - Always show if CrowdSec is present */}
              {hasCrowdSec && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <Shield className="h-4 w-4" />
                    <h3 className="font-semibold">CrowdSec Whitelist</h3>
                    <Badge>{whitelistData?.crowdsec?.length || 0} entries</Badge>
                  </div>
                  <div className="p-4 border rounded-lg bg-muted/50">
                    {whitelistData?.crowdsec && whitelistData.crowdsec.length > 0 ? (
                      <div className="flex flex-wrap gap-2">
                        {whitelistData.crowdsec.map((ip, index) => (
                          <Badge key={index} variant="secondary" className="font-mono">
                            {ip}
                          </Badge>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">No IPs whitelisted</p>
                    )}
                  </div>
                </div>
              )}

              {/* Proxy Whitelist - Only show if proxy container is present */}
              {showProxyOptions && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <Globe className="h-4 w-4" />
                    <h3 className="font-semibold">{proxyDisplayName} Whitelist</h3>
                    <Badge>{whitelistData?.traefik?.length || 0} entries</Badge>
                  </div>
                  <div className="p-4 border rounded-lg bg-muted/50">
                    {whitelistData?.traefik && whitelistData.traefik.length > 0 ? (
                      <div className="flex flex-wrap gap-2">
                        {whitelistData.traefik.map((ip, index) => (
                          <Badge key={index} variant="secondary" className="font-mono">
                            {ip}
                          </Badge>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">No IPs whitelisted</p>
                    )}
                  </div>
                </div>
              )}

              {/* Show message if no containers are detected */}
              {!hasCrowdSec && !showProxyOptions && (
                <div className="text-center py-8">
                  <p className="text-muted-foreground">
                    No whitelist-capable containers detected in current deployment
                  </p>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}