import { ProxyType } from '@/lib/proxy-types'
import { LogStats } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { 
  CheckCircle, 
  XCircle, 
  AlertTriangle, 
  Info, 
  FileText, 
  Activity,
  BarChart3
} from 'lucide-react'

interface LogParsingStatusProps {
  proxyType: ProxyType
  supportsLogs: boolean
  logStats?: LogStats | null
}

export function LogParsingStatus({ proxyType, logStats }: LogParsingStatusProps) {
  const proxyName = proxyType.charAt(0).toUpperCase() + proxyType.slice(1)

  const getLogParsingCapabilities = () => {
    switch (proxyType) {
      case 'traefik':
        return {
          supported: true,
          features: [
            'Access log parsing (CLF & JSON)',
            'Real-time error detection',
            'Advanced traffic analytics',
            'Status code analysis',
            'IP tracking & geolocation',
            'Request timing analysis',
            'User agent parsing',
            'Referrer tracking'
          ],
          format: 'Common Log Format / JSON / Structured',
          location: '/var/log/traefik/access.log',
          consistency: 'Excellent',
          performance: 'High',
          details: 'Traefik provides the most comprehensive log parsing with support for multiple formats and advanced analytics.'
        }
      case 'nginx':
        return {
          supported: true,
          features: [
            'NPM access log parsing',
            'Basic traffic analytics',
            'Error detection',
            'Status code tracking',
            'IP address monitoring',
            'Request method analysis'
          ],
          format: 'Nginx Combined Log Format',
          location: '/data/logs/proxy-host-*.log',
          consistency: 'Good',
          performance: 'Medium',
          details: 'Nginx Proxy Manager logs provide good coverage for basic analytics and monitoring.'
        }
      case 'caddy':
        return {
          supported: true,
          features: [
            'Structured JSON log parsing',
            'Request/response tracking',
            'Error detection',
            'Basic analytics'
          ],
          format: 'Caddy JSON Structured Logs',
          location: '/var/log/caddy/access.log',
          consistency: 'Good',
          performance: 'Medium',
          details: 'Caddy provides structured JSON logs that are easy to parse and analyze.',
          experimental: true
        }
      case 'haproxy':
        return {
          supported: true,
          features: [
            'Syslog format parsing',
            'Connection tracking',
            'Backend analysis',
            'Basic error detection'
          ],
          format: 'HAProxy Syslog Format',
          location: '/var/log/haproxy.log',
          consistency: 'Fair',
          performance: 'Low',
          details: 'HAProxy syslog format provides basic request tracking with limited analytics.',
          experimental: true
        }
      case 'zoraxy':
        return {
          supported: false,
          features: [],
          format: 'Not supported',
          location: 'N/A',
          reason: 'Zoraxy integration is experimental - log parsing not yet implemented',
          consistency: 'None',
          performance: 'None',
          details: 'Zoraxy log parsing will be added in future updates as the integration matures.'
        }
      case 'standalone':
        return {
          supported: false,
          features: [],
          format: 'Not applicable',
          location: 'N/A',
          reason: 'No reverse proxy in standalone mode',
          consistency: 'N/A',
          performance: 'N/A',
          details: 'Standalone mode focuses on CrowdSec logs only. Proxy logs are not available.'
        }
      default:
        return {
          supported: false,
          features: [],
          format: 'Unknown',
          location: 'N/A',
          reason: 'Unknown proxy type',
          consistency: 'Unknown',
          performance: 'Unknown',
          details: 'Unknown proxy type - log parsing capabilities cannot be determined.'
        }
    }
  }

  const capabilities = getLogParsingCapabilities()

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileText className="h-5 w-5" />
          Log Parsing Status
        </CardTitle>
        <CardDescription>
          Current log parsing capabilities for {proxyName}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Overall Status */}
        <div className="flex items-center justify-between p-4 border rounded-lg">
          <div className="flex items-center gap-3">
            {capabilities.supported ? (
              <CheckCircle className="h-5 w-5 text-green-500" />
            ) : (
              <XCircle className="h-5 w-5 text-red-500" />
            )}
            <div>
              <p className="font-medium">
                {capabilities.supported ? 'Log Parsing Supported' : 'Log Parsing Not Supported'}
              </p>
              <p className="text-sm text-muted-foreground">
                {capabilities.supported 
                  ? `${proxyName} logs can be parsed and analyzed`
                  : capabilities.reason || `${proxyName} does not support log parsing`
                }
              </p>
            </div>
          </div>
          <Badge variant={capabilities.supported ? 'default' : 'secondary'}>
            {capabilities.supported ? 'Available' : 'Not Available'}
          </Badge>
        </div>

        {/* Capabilities Details */}
        {capabilities.supported && (
          <div className="space-y-4">
            {/* Format and Performance Grid */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-3 border rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <BarChart3 className="h-4 w-4 text-muted-foreground" />
                  <span className="font-medium text-sm">Log Format</span>
                </div>
                <p className="text-sm text-muted-foreground">{capabilities.format}</p>
              </div>

              <div className="p-3 border rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <FileText className="h-4 w-4 text-muted-foreground" />
                  <span className="font-medium text-sm">Log Location</span>
                </div>
                <p className="text-sm text-muted-foreground font-mono">{capabilities.location}</p>
              </div>

              <div className="p-3 border rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle className="h-4 w-4 text-muted-foreground" />
                  <span className="font-medium text-sm">Consistency</span>
                </div>
                <Badge variant={
                  capabilities.consistency === 'Excellent' ? 'default' :
                  capabilities.consistency === 'Good' ? 'secondary' :
                  capabilities.consistency === 'Fair' ? 'outline' : 'destructive'
                }>
                  {capabilities.consistency}
                </Badge>
              </div>

              <div className="p-3 border rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <Activity className="h-4 w-4 text-muted-foreground" />
                  <span className="font-medium text-sm">Performance</span>
                </div>
                <Badge variant={
                  capabilities.performance === 'High' ? 'default' :
                  capabilities.performance === 'Medium' ? 'secondary' : 'outline'
                }>
                  {capabilities.performance}
                </Badge>
              </div>
            </div>

            {/* Details */}
            {capabilities.details && (
              <div className="p-4 bg-muted/50 rounded-lg">
                <p className="text-sm text-muted-foreground">
                  {capabilities.details}
                </p>
                {capabilities.experimental && (
                  <Badge variant="secondary" className="mt-2">
                    Experimental Feature
                  </Badge>
                )}
              </div>
            )}

            {/* Features */}
            <div>
              <h4 className="font-medium mb-2">Available Features</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {capabilities.features.map((feature, index) => (
                  <div key={index} className="flex items-center gap-2 text-sm">
                    <CheckCircle className="h-3 w-3 text-green-500" />
                    <span>{feature}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Statistics (if available) */}
            {logStats && (
              <div className="p-4 bg-muted/50 rounded-lg">
                <div className="flex items-center gap-2 mb-3">
                  <Activity className="h-4 w-4" />
                  <span className="font-medium">Current Statistics</span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <p className="text-muted-foreground">Total Lines</p>
                    <p className="font-medium">{logStats.total_lines.toLocaleString()}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Unique IPs</p>
                    <p className="font-medium">{logStats.top_ips.length}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Status Codes</p>
                    <p className="font-medium">{Object.keys(logStats.status_codes).length}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Errors</p>
                    <p className="font-medium">{logStats.error_entries.length}</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Alternative Solutions for Unsupported Proxies */}
        {!capabilities.supported && (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              <div className="space-y-2">
                <p>While {proxyName} doesn't support built-in log parsing, you can still monitor logs:</p>
                <ul className="list-disc list-inside space-y-1 text-sm">
                  <li>Access container logs directly via Docker commands</li>
                  <li>Use external log aggregation tools (ELK Stack, Grafana Loki)</li>
                  <li>Monitor CrowdSec logs for security events</li>
                  {proxyType === 'nginx' && (
                    <li>Configure NPM to export logs to external systems</li>
                  )}
                  {proxyType === 'caddy' && (
                    <li>Enable Caddy's structured logging and export to log collectors</li>
                  )}
                  {proxyType === 'haproxy' && (
                    <li>Configure HAProxy syslog output for external processing</li>
                  )}
                </ul>
              </div>
            </AlertDescription>
          </Alert>
        )}

        {/* Proxy-Specific Recommendations */}
        {proxyType === 'traefik' && capabilities.supported && (
          <Alert>
            <CheckCircle className="h-4 w-4" />
            <AlertDescription>
              Traefik provides the most comprehensive log analysis features. 
              Make sure access logs are enabled in your Traefik configuration for full functionality.
            </AlertDescription>
          </Alert>
        )}

        {proxyType === 'nginx' && capabilities.supported && (
          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              Nginx Proxy Manager log parsing provides basic analytics. 
              For advanced features, consider using Traefik or external log analysis tools.
            </AlertDescription>
          </Alert>
        )}

        {proxyType === 'zoraxy' && (
          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              Zoraxy integration is experimental. Log parsing capabilities may be added in future updates.
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  )
}