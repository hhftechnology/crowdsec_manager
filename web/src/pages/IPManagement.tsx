import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api, { UnbanRequest } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Globe, Shield, AlertTriangle, CheckCircle2, XCircle } from 'lucide-react'

export default function IPManagement() {
  const queryClient = useQueryClient()
  const [checkIP, setCheckIP] = useState('')
  const [unbanIP, setUnbanIP] = useState('')
  const [securityCheckIP, setSecurityCheckIP] = useState('')
  const [blockedCheckResult, setBlockedCheckResult] = useState<any>(null)
  const [securityCheckResult, setSecurityCheckResult] = useState<any>(null)

  const { data: publicIPData, isLoading: publicIPLoading } = useQuery({
    queryKey: ['publicIP'],
    queryFn: async () => {
      const response = await api.ip.getPublicIP()
      return response.data.data
    },
  })

  const blockedCheckMutation = useMutation({
    mutationFn: (ip: string) => api.ip.isBlocked(ip),
    onSuccess: (response) => {
      setBlockedCheckResult(response.data.data)
      toast.success('IP check completed')
    },
    onError: () => {
      toast.error('Failed to check IP status')
      setBlockedCheckResult(null)
    },
  })

  const securityCheckMutation = useMutation({
    mutationFn: (ip: string) => api.ip.checkSecurity(ip),
    onSuccess: (response) => {
      setSecurityCheckResult(response.data.data)
      toast.success('Security check completed')
    },
    onError: () => {
      toast.error('Failed to check IP security')
      setSecurityCheckResult(null)
    },
  })

  const unbanMutation = useMutation({
    mutationFn: (data: UnbanRequest) => api.ip.unban(data),
    onSuccess: () => {
      toast.success('IP unbanned successfully')
      setUnbanIP('')
      queryClient.invalidateQueries({ queryKey: ['publicIP'] })
    },
    onError: () => {
      toast.error('Failed to unban IP')
    },
  })

  const handleCheckBlocked = (e: React.FormEvent) => {
    e.preventDefault()
    if (!checkIP.trim()) {
      toast.error('Please enter an IP address')
      return
    }
    blockedCheckMutation.mutate(checkIP.trim())
  }

  const handleSecurityCheck = (e: React.FormEvent) => {
    e.preventDefault()
    if (!securityCheckIP.trim()) {
      toast.error('Please enter an IP address')
      return
    }
    securityCheckMutation.mutate(securityCheckIP.trim())
  }

  const handleUnban = (e: React.FormEvent) => {
    e.preventDefault()
    if (!unbanIP.trim()) {
      toast.error('Please enter an IP address')
      return
    }
    unbanMutation.mutate({ ip: unbanIP.trim() })
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">IP Management</h1>
        <p className="text-muted-foreground mt-2">
          Manage IP addresses, check status, and unban blocked IPs
        </p>
      </div>

      {/* Public IP Display */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5" />
            Your Public IP
          </CardTitle>
          <CardDescription>
            Current public IP address of this server
          </CardDescription>
        </CardHeader>
        <CardContent>
          {publicIPLoading ? (
            <div className="h-16 bg-muted animate-pulse rounded" />
          ) : (
            <div className="p-4 bg-muted rounded-lg">
              <p className="text-2xl font-mono font-bold text-center">
                {publicIPData?.ip || 'Unable to fetch'}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* IP Operations */}
      <Tabs defaultValue="check" className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="check">Check Blocked</TabsTrigger>
          <TabsTrigger value="security">Security Check</TabsTrigger>
          <TabsTrigger value="unban">Unban IP</TabsTrigger>
        </TabsList>

        {/* Check if IP is Blocked */}
        <TabsContent value="check">
          <Card>
            <CardHeader>
              <CardTitle>Check IP Block Status</CardTitle>
              <CardDescription>
                Verify if an IP address is currently blocked
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <form onSubmit={handleCheckBlocked} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="check-ip">IP Address</Label>
                  <div className="flex gap-2">
                    <Input
                      id="check-ip"
                      type="text"
                      placeholder="192.168.1.100"
                      value={checkIP}
                      onChange={(e) => setCheckIP(e.target.value)}
                      className="flex-1"
                    />
                    <Button
                      type="submit"
                      disabled={blockedCheckMutation.isPending}
                    >
                      {blockedCheckMutation.isPending ? 'Checking...' : 'Check'}
                    </Button>
                  </div>
                </div>
              </form>

              {blockedCheckResult && (
                <div className="p-4 border rounded-lg space-y-2">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-medium">IP Address</p>
                      <p className="text-sm font-mono text-muted-foreground">
                        {blockedCheckResult.ip}
                      </p>
                    </div>
                    {blockedCheckResult.blocked ? (
                      <Badge variant="destructive" className="flex items-center gap-1">
                        <XCircle className="h-3 w-3" />
                        Blocked
                      </Badge>
                    ) : (
                      <Badge variant="default" className="flex items-center gap-1">
                        <CheckCircle2 className="h-3 w-3" />
                        Not Blocked
                      </Badge>
                    )}
                  </div>
                  {blockedCheckResult.details && (
                    <div className="pt-2 border-t">
                      <p className="text-sm text-muted-foreground">
                        {blockedCheckResult.details}
                      </p>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Security Check */}
        <TabsContent value="security">
          <Card>
            <CardHeader>
              <CardTitle>IP Security Check</CardTitle>
              <CardDescription>
                Comprehensive security status check for an IP address
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <form onSubmit={handleSecurityCheck} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="security-ip">IP Address</Label>
                  <div className="flex gap-2">
                    <Input
                      id="security-ip"
                      type="text"
                      placeholder="192.168.1.100"
                      value={securityCheckIP}
                      onChange={(e) => setSecurityCheckIP(e.target.value)}
                      className="flex-1"
                    />
                    <Button
                      type="submit"
                      disabled={securityCheckMutation.isPending}
                    >
                      {securityCheckMutation.isPending ? 'Checking...' : 'Check'}
                    </Button>
                  </div>
                </div>
              </form>

              {securityCheckResult && (
                <div className="space-y-2">
                  <div className="p-4 border rounded-lg">
                    <div className="flex items-center justify-between mb-3">
                      <p className="font-semibold">Security Status</p>
                      <p className="font-mono text-sm text-muted-foreground">
                        {securityCheckResult.ip}
                      </p>
                    </div>
                    <div className="grid gap-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Shield className="h-4 w-4" />
                          <span className="text-sm">Blocked</span>
                        </div>
                        {securityCheckResult.is_blocked ? (
                          <Badge variant="destructive">Yes</Badge>
                        ) : (
                          <Badge variant="default">No</Badge>
                        )}
                      </div>

                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <CheckCircle2 className="h-4 w-4" />
                          <span className="text-sm">Whitelisted</span>
                        </div>
                        {securityCheckResult.is_whitelisted ? (
                          <Badge variant="default">Yes</Badge>
                        ) : (
                          <Badge variant="secondary">No</Badge>
                        )}
                      </div>

                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Shield className="h-4 w-4" />
                          <span className="text-sm">In CrowdSec</span>
                        </div>
                        {securityCheckResult.in_crowdsec ? (
                          <Badge variant="default">Yes</Badge>
                        ) : (
                          <Badge variant="secondary">No</Badge>
                        )}
                      </div>

                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Globe className="h-4 w-4" />
                          <span className="text-sm">In Traefik</span>
                        </div>
                        {securityCheckResult.in_traefik ? (
                          <Badge variant="default">Yes</Badge>
                        ) : (
                          <Badge variant="secondary">No</Badge>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Unban IP */}
        <TabsContent value="unban">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5" />
                Unban IP Address
              </CardTitle>
              <CardDescription>
                Remove an IP address from the blocklist
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleUnban} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="unban-ip">IP Address</Label>
                  <Input
                    id="unban-ip"
                    type="text"
                    placeholder="192.168.1.100"
                    value={unbanIP}
                    onChange={(e) => setUnbanIP(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    This will remove the IP from CrowdSec decisions and Traefik blocklists
                  </p>
                </div>

                <Button
                  type="submit"
                  className="w-full"
                  disabled={unbanMutation.isPending}
                  variant="destructive"
                >
                  {unbanMutation.isPending ? 'Unbanning...' : 'Unban IP Address'}
                </Button>
              </form>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Information */}
      <Card>
        <CardHeader>
          <CardTitle>IP Management Information</CardTitle>
          <CardDescription>
            Understanding IP operations and security
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>
            <strong>Block Status:</strong> Check if an IP is currently blocked by CrowdSec or Traefik.
          </p>
          <p>
            <strong>Security Check:</strong> Get comprehensive security information including whitelist
            status and presence in both CrowdSec and Traefik systems.
          </p>
          <p>
            <strong>Unban:</strong> Remove an IP from all blocklists. Use this carefully as it will
            immediately allow traffic from that IP address.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
