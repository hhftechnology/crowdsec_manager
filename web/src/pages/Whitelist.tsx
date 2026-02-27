import { useState, useMemo } from 'react'
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
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Shield, Globe, Plus, X, AlertCircle, Copy } from 'lucide-react'
import { PageHeader, QueryError } from '@/components/common'
import { ErrorContexts, getErrorMessage } from '@/lib/api/errors'

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/
const IPV4_CIDR_REGEX = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\/(?:[12]?\d|3[0-2])$/
// IPv6: full, compressed (::), mixed (::ffff:1.2.3.4), with zone ID (%eth0)
const IPV6_REGEX = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(%[a-zA-Z0-9]+)?$/
const IPV6_CIDR_REGEX = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\/(12[0-8]|1[01]\d|[1-9]?\d)$/

function isValidIP(ip: string): boolean {
  return IPV4_REGEX.test(ip) || IPV6_REGEX.test(ip)
}

function isValidCIDR(cidr: string): boolean {
  return IPV4_CIDR_REGEX.test(cidr) || IPV6_CIDR_REGEX.test(cidr)
}

function validateIP(ip: string): string | null {
  if (!ip.trim()) return null
  if (isValidIP(ip)) return null
  if (ip.includes('/')) return 'Use the CIDR tab for ranges'
  return 'Invalid IP address format (IPv4 or IPv6)'
}

function validateCIDR(cidr: string): string | null {
  if (!cidr.trim()) return null
  if (isValidCIDR(cidr)) return null
  if (!cidr.includes('/')) return 'CIDR must include a prefix (e.g., /24 for IPv4, /64 for IPv6)'
  return 'Invalid CIDR format (IPv4 /0-32, IPv6 /0-128)'
}

export default function Whitelist() {
  const queryClient = useQueryClient()
  const [manualIP, setManualIP] = useState('')
  const [cidr, setCidr] = useState('')
  const [addToCrowdSec, setAddToCrowdSec] = useState(true)
  const [addToTraefik, setAddToTraefik] = useState(true)
  const [followUpNotice, setFollowUpNotice] = useState<string | null>(null)

  const { data: whitelistData, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['whitelist'],
    queryFn: async () => {
      const response = await api.whitelist.view()
      return response.data.data ?? null
    },
  })

  const { data: publicIPData } = useQuery({
    queryKey: ['publicIP'],
    queryFn: async () => {
      const response = await api.ip.getPublicIP()
      return response.data.data ?? null
    },
  })

  const whitelistCurrentMutation = useMutation({
    mutationFn: () => api.whitelist.whitelistCurrent(),
    onSuccess: (response) => {
      toast.success(response.data.message || 'Current IP whitelisted successfully')
      const message = response.data.message || ''
      if (message.toLowerCase().includes('restart') || message.toLowerCase().includes('reload failed')) {
        setFollowUpNotice(message)
      }
      queryClient.invalidateQueries({ queryKey: ['whitelist'] })
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, 'Failed to whitelist current IP', ErrorContexts.WhitelistCurrentAdd))
    },
  })

  const whitelistManualMutation = useMutation({
    mutationFn: (data: WhitelistRequest) => api.whitelist.whitelistManual(data),
    onSuccess: (response) => {
      toast.success(response.data.message || 'IP whitelisted successfully')
      const message = response.data.message || ''
      if (message.toLowerCase().includes('restart') || message.toLowerCase().includes('reload failed')) {
        setFollowUpNotice(message)
      }
      setManualIP('')
      queryClient.invalidateQueries({ queryKey: ['whitelist'] })
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, 'Failed to whitelist IP', ErrorContexts.WhitelistManualAdd))
    },
  })

  const whitelistCIDRMutation = useMutation({
    mutationFn: (data: WhitelistRequest) => api.whitelist.whitelistCIDR(data),
    onSuccess: (response) => {
      toast.success(response.data.message || 'CIDR range whitelisted successfully')
      const message = response.data.message || ''
      if (message.toLowerCase().includes('restart') || message.toLowerCase().includes('reload failed')) {
        setFollowUpNotice(message)
      }
      setCidr('')
      queryClient.invalidateQueries({ queryKey: ['whitelist'] })
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, 'Failed to whitelist CIDR range', ErrorContexts.WhitelistCIDRAdd))
    },
  })

  const comprehensiveMutation = useMutation({
    mutationFn: (data: WhitelistRequest) => api.whitelist.setupComprehensive(data),
    onSuccess: (response) => {
      toast.success(response.data.message || 'Comprehensive whitelist setup completed')
      const message = response.data.message || ''
      if (message.toLowerCase().includes('restart') || message.toLowerCase().includes('reload failed')) {
        setFollowUpNotice(message)
      }
      queryClient.invalidateQueries({ queryKey: ['whitelist'] })
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, 'Failed to setup comprehensive whitelist', ErrorContexts.WhitelistComprehensiveSetup))
    },
  })

  const removeMutation = useMutation({
    mutationFn: (data: { ip: string; remove_from_crowdsec: boolean; remove_from_traefik: boolean }) =>
      api.whitelist.remove(data),
    onSuccess: (response, vars) => {
      toast.success(response.data.message || `IP ${vars.ip} removed from whitelist`)
      queryClient.invalidateQueries({ queryKey: ['whitelist'] })
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, 'Failed to remove IP from whitelist', ErrorContexts.WhitelistRemove))
    },
  })

  const ipError = useMemo(() => validateIP(manualIP), [manualIP])
  const cidrError = useMemo(() => validateCIDR(cidr), [cidr])

  // Check for duplicates — only true when the value already exists in every
  // selected destination. If a toggle is off, that destination is ignored.
  const isIPDuplicate = useMemo(() => {
    if (!manualIP || !whitelistData) return false
    const inCrowdSec = (whitelistData.crowdsec || []).includes(manualIP)
    const inTraefik = (whitelistData.traefik || []).includes(manualIP)
    const crowdSecSatisfied = !addToCrowdSec || inCrowdSec
    const traefikSatisfied = !addToTraefik || inTraefik
    return crowdSecSatisfied && traefikSatisfied
  }, [manualIP, whitelistData, addToCrowdSec, addToTraefik])

  const isCIDRDuplicate = useMemo(() => {
    if (!cidr || !whitelistData) return false
    const inCrowdSec = (whitelistData.crowdsec || []).includes(cidr)
    const inTraefik = (whitelistData.traefik || []).includes(cidr)
    const crowdSecSatisfied = !addToCrowdSec || inCrowdSec
    const traefikSatisfied = !addToTraefik || inTraefik
    return crowdSecSatisfied && traefikSatisfied
  }, [cidr, whitelistData, addToCrowdSec, addToTraefik])

  const handleWhitelistManual = (e: React.FormEvent) => {
    e.preventDefault()
    if (!manualIP.trim() || ipError) {
      toast.error(ipError || 'Please enter an IP address')
      return
    }
    whitelistManualMutation.mutate({
      ip: manualIP,
      add_to_crowdsec: addToCrowdSec,
      add_to_traefik: addToTraefik,
    })
  }

  const handleWhitelistCIDR = (e: React.FormEvent) => {
    e.preventDefault()
    if (!cidr.trim() || cidrError) {
      toast.error(cidrError || 'Please enter a CIDR range')
      return
    }
    whitelistCIDRMutation.mutate({
      ip: '',
      cidr: cidr,
      add_to_crowdsec: addToCrowdSec,
      add_to_traefik: addToTraefik,
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
      add_to_traefik: true,
      comprehensive: true,
    })
  }

  const handleRemoveIP = (ip: string, source: 'crowdsec' | 'traefik') => {
    removeMutation.mutate({
      ip,
      remove_from_crowdsec: source === 'crowdsec',
      remove_from_traefik: source === 'traefik',
    })
  }

  const handleCopyIP = async (ip: string) => {
    try {
      await navigator.clipboard.writeText(ip)
      toast.success('IP copied to clipboard')
    } catch {
      toast.error('Failed to copy IP')
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Whitelist Management" description="Manage whitelisted IPs and CIDR ranges across CrowdSec and Traefik" />

      {followUpNotice && (
        <Alert>
          <AlertTitle>Action required</AlertTitle>
          <AlertDescription>{followUpNotice}</AlertDescription>
        </Alert>
      )}

      {isError && <QueryError error={error} onRetry={refetch} />}

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
              onClick={() => whitelistCurrentMutation.mutate()}
              disabled={whitelistCurrentMutation.isPending || !publicIPData?.ip}
            >
              <Shield className="h-4 w-4" />
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
              <Plus className="h-4 w-4" />
              Setup Comprehensive Whitelist
            </Button>
            <p className="text-xs text-muted-foreground mt-2 text-center">
              Adds your IP to all whitelist locations (CrowdSec + Traefik)
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
                    placeholder="192.168.1.100 or 2a01:4f8:1c0c::1"
                    value={manualIP}
                    onChange={(e) => setManualIP(e.target.value)}
                    className={ipError ? 'border-destructive' : isIPDuplicate ? 'border-yellow-500' : ''}
                  />
                  {ipError && (
                    <p className="text-sm text-destructive flex items-center gap-1">
                      <AlertCircle className="h-3 w-3" />{ipError}
                    </p>
                  )}
                  {!ipError && isIPDuplicate && (
                    <p className="text-sm text-yellow-600 dark:text-yellow-400 flex items-center gap-1">
                      <AlertCircle className="h-3 w-3" />This IP is already whitelisted
                    </p>
                  )}
                </div>

                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label>Add to CrowdSec</Label>
                      <p className="text-sm text-muted-foreground">Add to CrowdSec whitelist</p>
                    </div>
                    <Switch checked={addToCrowdSec} onCheckedChange={setAddToCrowdSec} />
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label>Add to Traefik</Label>
                      <p className="text-sm text-muted-foreground">Add to Traefik whitelist</p>
                    </div>
                    <Switch checked={addToTraefik} onCheckedChange={setAddToTraefik} />
                  </div>
                </div>

                <Button
                  type="submit"
                  className="w-full"
                  disabled={whitelistManualMutation.isPending || !!ipError}
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
                    placeholder="192.168.1.0/24 or 2a01:4f8::/32"
                    value={cidr}
                    onChange={(e) => setCidr(e.target.value)}
                    className={cidrError ? 'border-destructive' : isCIDRDuplicate ? 'border-yellow-500' : ''}
                  />
                  {cidrError && (
                    <p className="text-sm text-destructive flex items-center gap-1">
                      <AlertCircle className="h-3 w-3" />{cidrError}
                    </p>
                  )}
                  {!cidrError && isCIDRDuplicate && (
                    <p className="text-sm text-yellow-600 dark:text-yellow-400 flex items-center gap-1">
                      <AlertCircle className="h-3 w-3" />This CIDR is already whitelisted
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground">
                    Example: 192.168.1.0/24, 10.0.0.0/8, or 2a01:4f8::/32
                  </p>
                </div>

                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label>Add to CrowdSec</Label>
                      <p className="text-sm text-muted-foreground">Add to CrowdSec whitelist</p>
                    </div>
                    <Switch checked={addToCrowdSec} onCheckedChange={setAddToCrowdSec} />
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label>Add to Traefik</Label>
                      <p className="text-sm text-muted-foreground">Add to Traefik whitelist</p>
                    </div>
                    <Switch checked={addToTraefik} onCheckedChange={setAddToTraefik} />
                  </div>
                </div>

                <Button
                  type="submit"
                  className="w-full"
                  disabled={whitelistCIDRMutation.isPending || !!cidrError}
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
              {/* CrowdSec Whitelist */}
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  <h3 className="font-semibold">CrowdSec Whitelist</h3>
                  <Badge>{whitelistData?.crowdsec?.length || 0} entries</Badge>
                </div>
                <div className="p-4 border rounded-lg bg-muted/50">
                  {whitelistData?.crowdsec && whitelistData.crowdsec.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {whitelistData.crowdsec.map((ip: string, index: number) => (
                        <Badge key={index} variant="secondary" className="font-mono gap-1 pr-1">
                          {ip}
                          <button
                            className="ml-1 rounded-full p-0.5 hover:bg-muted hover:text-foreground transition-colors"
                            onClick={() => handleCopyIP(ip)}
                          >
                            <Copy className="h-3 w-3" />
                          </button>
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <button className="ml-1 rounded-full p-0.5 hover:bg-destructive/20 hover:text-destructive transition-colors">
                                <X className="h-3 w-3" />
                              </button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                              <AlertDialogHeader>
                                <AlertDialogTitle>Remove IP from CrowdSec?</AlertDialogTitle>
                                <AlertDialogDescription>
                                  Remove <strong className="font-mono">{ip}</strong> from the CrowdSec whitelist. This may cause the IP to be blocked if it triggers a scenario.
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>Cancel</AlertDialogCancel>
                                <AlertDialogAction
                                  onClick={() => handleRemoveIP(ip, 'crowdsec')}
                                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                >
                                  Remove
                                </AlertDialogAction>
                              </AlertDialogFooter>
                            </AlertDialogContent>
                          </AlertDialog>
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">No IPs whitelisted</p>
                  )}
                </div>
              </div>

              {/* Traefik Whitelist */}
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4" />
                  <h3 className="font-semibold">Traefik Whitelist</h3>
                  <Badge>{whitelistData?.traefik?.length || 0} entries</Badge>
                </div>
                <div className="p-4 border rounded-lg bg-muted/50">
                  {whitelistData?.traefik && whitelistData.traefik.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {whitelistData.traefik.map((ip: string, index: number) => (
                        <Badge key={index} variant="secondary" className="font-mono gap-1 pr-1">
                          {ip}
                          <button
                            className="ml-1 rounded-full p-0.5 hover:bg-muted hover:text-foreground transition-colors"
                            onClick={() => handleCopyIP(ip)}
                          >
                            <Copy className="h-3 w-3" />
                          </button>
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <button className="ml-1 rounded-full p-0.5 hover:bg-destructive/20 hover:text-destructive transition-colors">
                                <X className="h-3 w-3" />
                              </button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                              <AlertDialogHeader>
                                <AlertDialogTitle>Remove IP from Traefik?</AlertDialogTitle>
                                <AlertDialogDescription>
                                  Remove <strong className="font-mono">{ip}</strong> from the Traefik whitelist.
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>Cancel</AlertDialogCancel>
                                <AlertDialogAction
                                  onClick={() => handleRemoveIP(ip, 'traefik')}
                                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                >
                                  Remove
                                </AlertDialogAction>
                              </AlertDialogFooter>
                            </AlertDialogContent>
                          </AlertDialog>
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">No IPs whitelisted</p>
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
