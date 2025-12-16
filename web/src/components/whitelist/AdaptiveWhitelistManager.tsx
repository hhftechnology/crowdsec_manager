import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { WhitelistRequest } from '@/lib/api'
import { ProxyType, Feature } from '@/lib/proxy-types'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Separator } from '@/components/ui/separator'
import { 
  Shield, 
  Globe, 
  Plus, 
  AlertTriangle, 
  Info,
  CheckCircle,
  XCircle,
  Network
} from 'lucide-react'
import { FeatureAvailabilityIndicator } from './FeatureAvailabilityIndicator'
import { IPValidationInput } from './IPValidationInput'
import { BatchOperationsPanel } from './BatchOperationsPanel'

interface AdaptiveWhitelistManagerProps {
  proxyType: ProxyType
  supportedFeatures: Feature[]
}

export function AdaptiveWhitelistManager({ proxyType, supportedFeatures }: AdaptiveWhitelistManagerProps) {
  const queryClient = useQueryClient()
  const [manualIP, setManualIP] = useState('')
  const [cidr, setCidr] = useState('')
  const [addToCrowdSec, setAddToCrowdSec] = useState(true)
  const [addToProxy, setAddToProxy] = useState(supportedFeatures.includes('whitelist'))

  const supportsWhitelist = supportedFeatures.includes('whitelist')
  const proxyName = proxyType.charAt(0).toUpperCase() + proxyType.slice(1)

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
      add_to_traefik: addToProxy && proxyType === 'traefik', // Backward compatibility
      add_to_proxy: addToProxy && supportsWhitelist,
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
      add_to_traefik: addToProxy && proxyType === 'traefik', // Backward compatibility
      add_to_proxy: addToProxy && supportsWhitelist,
    })
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Reverse Proxy Whitelist Management</h1>
        <p className="text-muted-foreground mt-2">
          Manage whitelisted IPs and CIDR ranges across CrowdSec and {proxyName}
        </p>
      </div>

      {/* Proxy Feature Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Network className="h-5 w-5" />
            Proxy Configuration
          </CardTitle>
          <CardDescription>
            Current proxy type and available whitelist features
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between p-4 border rounded-lg">
            <div>
              <p className="font-medium">Current Proxy Type</p>
              <p className="text-sm text-muted-foreground">
                {proxyName} {proxyType === 'zoraxy' && '(Experimental)'}
              </p>
            </div>
            <Badge variant="outline">{proxyName}</Badge>
          </div>

          <FeatureAvailabilityIndicator
            feature="whitelist"
            available={supportsWhitelist}
            proxyType={proxyType}
            description="Manage IP whitelists at the reverse proxy level"
          />

          {!supportsWhitelist && (
            <Alert>
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                {proxyName} does not support proxy-level whitelist management. 
                You can still manage CrowdSec whitelists, which will affect all traffic processing.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Quick Whitelist */}
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
                <IPValidationInput
                  value={manualIP}
                  onChange={setManualIP}
                  placeholder="192.168.1.100"
                  label="IP Address"
                />

                <Separator />

                <div className="space-y-4">
                  <h4 className="font-medium">Whitelist Destinations</h4>
                  
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="flex items-center gap-2">
                        <Shield className="h-4 w-4" />
                        Add to CrowdSec
                      </Label>
                      <p className="text-sm text-muted-foreground">
                        Add to CrowdSec allowlist (affects all traffic processing)
                      </p>
                    </div>
                    <Switch
                      checked={addToCrowdSec}
                      onCheckedChange={setAddToCrowdSec}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="flex items-center gap-2">
                        <Globe className="h-4 w-4" />
                        Add to {proxyName}
                        {!supportsWhitelist && (
                          <Badge variant="secondary" className="text-xs">
                            Not Available
                          </Badge>
                        )}
                      </Label>
                      <p className="text-sm text-muted-foreground">
                        {supportsWhitelist 
                          ? `Add to ${proxyName} reverse proxy whitelist`
                          : `${proxyName} does not support proxy-level whitelisting`
                        }
                      </p>
                    </div>
                    <Switch
                      checked={addToProxy && supportsWhitelist}
                      onCheckedChange={setAddToProxy}
                      disabled={!supportsWhitelist}
                    />
                  </div>
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
                <IPValidationInput
                  value={cidr}
                  onChange={setCidr}
                  placeholder="192.168.1.0/24"
                  label="CIDR Range"
                  type="cidr"
                  helperText="Example: 192.168.1.0/24 or 10.0.0.0/8"
                />

                <Separator />

                <div className="space-y-4">
                  <h4 className="font-medium">Whitelist Destinations</h4>
                  
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="flex items-center gap-2">
                        <Shield className="h-4 w-4" />
                        Add to CrowdSec
                      </Label>
                      <p className="text-sm text-muted-foreground">
                        Add to CrowdSec allowlist (affects all traffic processing)
                      </p>
                    </div>
                    <Switch
                      checked={addToCrowdSec}
                      onCheckedChange={setAddToCrowdSec}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="flex items-center gap-2">
                        <Globe className="h-4 w-4" />
                        Add to {proxyName}
                        {!supportsWhitelist && (
                          <Badge variant="secondary" className="text-xs">
                            Not Available
                          </Badge>
                        )}
                      </Label>
                      <p className="text-sm text-muted-foreground">
                        {supportsWhitelist 
                          ? `Add to ${proxyName} reverse proxy whitelist`
                          : `${proxyName} does not support proxy-level whitelisting`
                        }
                      </p>
                    </div>
                    <Switch
                      checked={addToProxy && supportsWhitelist}
                      onCheckedChange={setAddToProxy}
                      disabled={!supportsWhitelist}
                    />
                  </div>
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

      {/* Batch Operations */}
      <BatchOperationsPanel 
        proxyType={proxyType}
        supportedFeatures={supportedFeatures}
      />

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
              {/* CrowdSec Whitelist */}
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  <h3 className="font-semibold">CrowdSec Allowlist</h3>
                  <Badge>{whitelistData?.crowdsec?.length || 0} entries</Badge>
                  <CheckCircle className="h-4 w-4 text-green-500" />
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

              {/* Proxy Whitelist */}
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4" />
                  <h3 className="font-semibold">{proxyName} Whitelist</h3>
                  <Badge>{whitelistData?.proxy?.length || whitelistData?.[proxyType]?.length || 0} entries</Badge>
                  {supportsWhitelist ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <XCircle className="h-4 w-4 text-muted-foreground" />
                  )}
                </div>
                <div className="p-4 border rounded-lg bg-muted/50">
                  {supportsWhitelist ? (
                    <>
                      {(whitelistData?.proxy || whitelistData?.[proxyType]) && 
                       (whitelistData?.proxy?.length > 0 || whitelistData?.[proxyType]?.length > 0) ? (
                        <div className="flex flex-wrap gap-2">
                          {(whitelistData.proxy || whitelistData[proxyType]).map((ip, index) => (
                            <Badge key={index} variant="secondary" className="font-mono">
                              {ip}
                            </Badge>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm text-muted-foreground">No IPs whitelisted</p>
                      )}
                    </>
                  ) : (
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Info className="h-4 w-4" />
                      <span>{proxyName} does not support proxy-level whitelist management</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}