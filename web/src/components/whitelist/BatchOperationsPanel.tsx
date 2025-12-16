import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api from '@/lib/api'
import { ProxyType, Feature } from '@/lib/proxy-types'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Separator } from '@/components/ui/separator'
import { Progress } from '@/components/ui/progress'
import { 
  Upload, 
  Download, 
  Trash2, 
  Shield, 
  Globe, 
  AlertTriangle,
  CheckCircle,
  Info,
  FileText
} from 'lucide-react'

interface BatchOperationsPanelProps {
  proxyType: ProxyType
  supportedFeatures: Feature[]
}

interface BatchResult {
  ip: string
  success: boolean
  message: string
}

export function BatchOperationsPanel({ proxyType, supportedFeatures }: BatchOperationsPanelProps) {
  const queryClient = useQueryClient()
  const [batchIPs, setBatchIPs] = useState('')
  const [addToCrowdSec, setAddToCrowdSec] = useState(true)
  const [addToProxy, setAddToProxy] = useState(supportedFeatures.includes('whitelist'))
  const [batchResults, setBatchResults] = useState<BatchResult[]>([])
  const [isProcessing, setIsProcessing] = useState(false)
  const [progress, setProgress] = useState(0)

  const supportsWhitelist = supportedFeatures.includes('whitelist')
  const proxyName = proxyType.charAt(0).toUpperCase() + proxyType.slice(1)

  const batchWhitelistMutation = useMutation({
    mutationFn: async (ips: string[]) => {
      const results: BatchResult[] = []
      setIsProcessing(true)
      setProgress(0)

      for (let i = 0; i < ips.length; i++) {
        const ip = ips[i].trim()
        if (!ip) continue

        try {
          await api.whitelist.whitelistManual({
            ip,
            add_to_crowdsec: addToCrowdSec,
            add_to_traefik: addToProxy && proxyType === 'traefik',
            add_to_proxy: addToProxy && supportsWhitelist,
          })
          
          results.push({
            ip,
            success: true,
            message: 'Successfully whitelisted'
          })
        } catch (error) {
          results.push({
            ip,
            success: false,
            message: error instanceof Error ? error.message : 'Unknown error'
          })
        }

        setProgress(((i + 1) / ips.length) * 100)
      }

      return results
    },
    onSuccess: (results) => {
      setBatchResults(results)
      setIsProcessing(false)
      
      const successful = results.filter(r => r.success).length
      const failed = results.filter(r => !r.success).length
      
      if (failed === 0) {
        toast.success(`Successfully whitelisted ${successful} IP addresses`)
      } else if (successful === 0) {
        toast.error(`Failed to whitelist all ${failed} IP addresses`)
      } else {
        toast.warning(`Whitelisted ${successful} IPs, ${failed} failed`)
      }
      
      queryClient.invalidateQueries({ queryKey: ['whitelist'] })
    },
    onError: () => {
      setIsProcessing(false)
      toast.error('Batch operation failed')
    },
  })

  const handleBatchWhitelist = () => {
    const ips = batchIPs
      .split('\n')
      .map(ip => ip.trim())
      .filter(ip => ip.length > 0)

    if (ips.length === 0) {
      toast.error('Please enter at least one IP address')
      return
    }

    // Basic validation
    const invalidIPs = ips.filter(ip => {
      const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
      const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$/
      return !ipv4Regex.test(ip) && !cidrRegex.test(ip)
    })

    if (invalidIPs.length > 0) {
      toast.error(`Invalid IP addresses found: ${invalidIPs.slice(0, 3).join(', ')}${invalidIPs.length > 3 ? '...' : ''}`)
      return
    }

    batchWhitelistMutation.mutate(ips)
  }

  const handleExportWhitelist = async () => {
    try {
      const response = await api.whitelist.view()
      const data = response.data.data
      
      const exportData = {
        timestamp: new Date().toISOString(),
        proxy_type: proxyType,
        crowdsec: data.crowdsec || [],
        proxy: data.proxy || data[proxyType] || []
      }
      
      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `whitelist-export-${proxyType}-${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      
      toast.success('Whitelist exported successfully')
    } catch (error) {
      toast.error('Failed to export whitelist')
    }
  }

  const clearBatchResults = () => {
    setBatchResults([])
    setProgress(0)
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Upload className="h-5 w-5" />
          Batch Operations
        </CardTitle>
        <CardDescription>
          Perform bulk whitelist operations and manage multiple IPs at once
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Batch Import */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="font-medium">Batch Import IPs</h4>
            <Badge variant="outline">{batchIPs.split('\n').filter(ip => ip.trim()).length} IPs</Badge>
          </div>
          
          <div className="space-y-2">
            <Label htmlFor="batch-ips">IP Addresses (one per line)</Label>
            <Textarea
              id="batch-ips"
              placeholder={`192.168.1.100
10.0.0.50
172.16.0.0/24
203.0.113.1`}
              value={batchIPs}
              onChange={(e) => setBatchIPs(e.target.value)}
              rows={6}
              className="font-mono text-sm"
            />
            <p className="text-xs text-muted-foreground">
              Supports both individual IPs and CIDR ranges. One entry per line.
            </p>
          </div>

          <Separator />

          <div className="space-y-4">
            <h5 className="font-medium">Batch Destinations</h5>
            
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label className="flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Add to CrowdSec
                </Label>
                <p className="text-sm text-muted-foreground">
                  Add all IPs to CrowdSec allowlist
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
                    ? `Add all IPs to ${proxyName} reverse proxy whitelist`
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

          {isProcessing && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>Processing batch operation...</span>
                <span>{Math.round(progress)}%</span>
              </div>
              <Progress value={progress} className="w-full" />
            </div>
          )}

          <Button
            onClick={handleBatchWhitelist}
            disabled={isProcessing || !batchIPs.trim()}
            className="w-full"
          >
            {isProcessing ? 'Processing...' : 'Whitelist All IPs'}
          </Button>
        </div>

        {/* Batch Results */}
        {batchResults.length > 0 && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h4 className="font-medium">Batch Results</h4>
              <Button variant="outline" size="sm" onClick={clearBatchResults}>
                <Trash2 className="h-4 w-4 mr-2" />
                Clear Results
              </Button>
            </div>
            
            <div className="max-h-48 overflow-y-auto space-y-2">
              {batchResults.map((result, index) => (
                <div
                  key={index}
                  className={`flex items-center justify-between p-3 rounded-lg border ${
                    result.success ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    {result.success ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <AlertTriangle className="h-4 w-4 text-red-500" />
                    )}
                    <span className="font-mono text-sm">{result.ip}</span>
                  </div>
                  <span className={`text-xs ${
                    result.success ? 'text-green-600' : 'text-red-600'
                  }`}>
                    {result.message}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        <Separator />

        {/* Export/Import */}
        <div className="space-y-4">
          <h4 className="font-medium">Export & Import</h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Button
              variant="outline"
              onClick={handleExportWhitelist}
              className="flex items-center gap-2"
            >
              <Download className="h-4 w-4" />
              Export Current Whitelist
            </Button>
            
            <Button
              variant="outline"
              disabled
              className="flex items-center gap-2"
            >
              <FileText className="h-4 w-4" />
              Import from File
              <Badge variant="secondary" className="text-xs ml-2">
                Coming Soon
              </Badge>
            </Button>
          </div>
          
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              Export creates a JSON file with current whitelist entries from both CrowdSec and {proxyName}. 
              Import functionality will be available in a future update.
            </AlertDescription>
          </Alert>
        </div>
      </CardContent>
    </Card>
  )
}