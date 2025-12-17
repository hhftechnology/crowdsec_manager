import { useState } from 'react'
import { ProxyType } from '@/lib/proxy-types'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { ScrollArea } from '@/components/ui/scroll-area'
import { 
  FileText, 
  Download, 
  Copy, 
  Eye, 
  EyeOff,
  AlertTriangle,
  Info,
  CheckCircle,
  Clock,
  Activity
} from 'lucide-react'
import { toast } from 'sonner'

interface LogViewerProps {
  logType: 'crowdsec' | 'proxy'
  proxyType: ProxyType
  crowdsecLogs?: { logs: string }
  proxyLogs?: { logs: string; service?: string }
  isLoading: boolean
  supportsLogs: boolean
  tailLines: string
}

export function LogViewer({ 
  logType, 
  proxyType, 
  crowdsecLogs, 
  proxyLogs, 
  isLoading, 
  supportsLogs,
  tailLines 
}: LogViewerProps) {
  const [showTimestamps, setShowTimestamps] = useState(true)
  const [wrapLines, setWrapLines] = useState(false)

  const getCurrentLogs = () => {
    if (logType === 'crowdsec') {
      return crowdsecLogs?.logs || ''
    } else if (logType === 'proxy' && supportsLogs) {
      return proxyLogs?.logs || ''
    }
    return ''
  }

  const formatLogLine = (line: string): { timestamp?: string; level?: string; message: string; formatted: string; metadata?: Record<string, any> } => {
    if (!line.trim()) {
      return { message: '', formatted: line }
    }

    // Try to parse different log formats based on proxy type and log type
    if (logType === 'crowdsec') {
      // CrowdSec log format: timestamp level message
      const crowdsecMatch = line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+(\w+)\s+(.+)$/)
      if (crowdsecMatch) {
        const [, timestamp, level, message] = crowdsecMatch
        return {
          timestamp,
          level: level.toUpperCase(),
          message,
          formatted: line,
          metadata: { source: 'crowdsec' }
        }
      }
      
      // Alternative CrowdSec format with component
      const crowdsecAltMatch = line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+(\w+)\s+\[([^\]]+)\]\s+(.+)$/)
      if (crowdsecAltMatch) {
        const [, timestamp, level, component, message] = crowdsecAltMatch
        return {
          timestamp,
          level: level.toUpperCase(),
          message: `[${component}] ${message}`,
          formatted: line,
          metadata: { source: 'crowdsec', component }
        }
      }
    } else if (logType === 'proxy') {
      // Handle different proxy log formats with enhanced parsing
      if (proxyType === 'traefik') {
        // Traefik JSON structured logs
        if (line.startsWith('{')) {
          try {
            const json = JSON.parse(line)
            const method = json.RequestMethod || json.method || ''
            const path = json.RequestPath || json.path || json.uri || ''
            const status = json.DownstreamStatus || json.status || ''
            const clientIP = json.ClientAddr || json.remote_addr || json.ip || ''
            const duration = json.Duration || json.duration || ''
            
            return {
              timestamp: json.time || json.timestamp || json.StartUTC,
              level: (status && parseInt(status) >= 400) ? 'ERROR' : 'INFO',
              message: `${clientIP} ${method} ${path} → ${status}${duration ? ` (${duration})` : ''}`,
              formatted: line,
              metadata: { 
                source: 'traefik', 
                format: 'json',
                method,
                path,
                status,
                clientIP,
                duration
              }
            }
          } catch {
            // Not valid JSON, continue to other formats
          }
        }
        
        // Common log format: IP - - [timestamp] "method path protocol" status size
        const accessMatch = line.match(/^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)(?:\s+"([^"]*)"\s+"([^"]*)")?/)
        if (accessMatch) {
          const [, ip, timestamp, request, status, size, referer, userAgent] = accessMatch
          return {
            timestamp,
            level: parseInt(status) >= 400 ? 'ERROR' : 'INFO',
            message: `${ip} ${request} → ${status} (${size} bytes)`,
            formatted: line,
            metadata: { 
              source: 'traefik', 
              format: 'clf',
              ip,
              request,
              status,
              size,
              referer,
              userAgent
            }
          }
        }
      } else if (proxyType === 'nginx') {
        // Nginx Proxy Manager enhanced parsing
        // NPM JSON format (if configured)
        if (line.startsWith('{')) {
          try {
            const json = JSON.parse(line)
            return {
              timestamp: json.time_local || json.timestamp,
              level: (json.status && parseInt(json.status) >= 400) ? 'ERROR' : 'INFO',
              message: `${json.remote_addr || json.ip} ${json.request || ''} → ${json.status || ''} (${json.body_bytes_sent || 0} bytes)`,
              formatted: line,
              metadata: { 
                source: 'nginx', 
                format: 'json',
                ...json
              }
            }
          } catch {
            // Not JSON, continue
          }
        }
        
        // Standard NPM log format with enhanced regex
        const npmMatch = line.match(/^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"(?:\s+"([^"]*)")?/)
        if (npmMatch) {
          const [, ip, timestamp, request, status, size, referer, userAgent, forwardedFor] = npmMatch
          return {
            timestamp,
            level: parseInt(status) >= 400 ? 'ERROR' : 'INFO',
            message: `${ip} ${request} → ${status} (${size} bytes)`,
            formatted: line,
            metadata: { 
              source: 'nginx', 
              format: 'combined',
              ip,
              request,
              status,
              size,
              referer,
              userAgent,
              forwardedFor
            }
          }
        }
        
        // Simplified NPM format
        const npmSimpleMatch = line.match(/^(\S+)\s+.*\[([^\]]+)\].*"([^"]+)"\s+(\d+)/)
        if (npmSimpleMatch) {
          const [, ip, timestamp, request, status] = npmSimpleMatch
          return {
            timestamp,
            level: parseInt(status) >= 400 ? 'ERROR' : 'INFO',
            message: `${ip} ${request} → ${status}`,
            formatted: line,
            metadata: { 
              source: 'nginx', 
              format: 'simple',
              ip,
              request,
              status
            }
          }
        }
      } else if (proxyType === 'caddy') {
        // Caddy structured log format (JSON)
        if (line.startsWith('{')) {
          try {
            const json = JSON.parse(line)
            const method = json.request?.method || ''
            const uri = json.request?.uri || json.request?.path || ''
            const status = json.status || json.resp_status || ''
            const clientIP = json.request?.remote_addr || json.request?.client_ip || ''
            
            return {
              timestamp: json.ts ? new Date(json.ts * 1000).toISOString() : json.time,
              level: json.level?.toUpperCase() || ((status && parseInt(status) >= 400) ? 'ERROR' : 'INFO'),
              message: json.msg || `${clientIP} ${method} ${uri} → ${status}`,
              formatted: line,
              metadata: { 
                source: 'caddy', 
                format: 'json',
                method,
                uri,
                status,
                clientIP,
                ...json
              }
            }
          } catch {
            // Not JSON, treat as regular log
          }
        }
        
        // Caddy common log format fallback
        const caddyMatch = line.match(/^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)/)
        if (caddyMatch) {
          const [, ip, timestamp, request, status, size] = caddyMatch
          return {
            timestamp,
            level: parseInt(status) >= 400 ? 'ERROR' : 'INFO',
            message: `${ip} ${request} → ${status} (${size} bytes)`,
            formatted: line,
            metadata: { 
              source: 'caddy', 
              format: 'clf',
              ip,
              request,
              status,
              size
            }
          }
        }
      } else if (proxyType === 'haproxy') {
        // HAProxy syslog format: timestamp process[pid]: client_ip:port [timestamp] frontend backend/server timers status bytes
        const haproxyMatch = line.match(/^(\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\[\d+\]:\s+(\S+:\d+)\s+\[([^\]]+)\]\s+(\S+)\s+(\S+\/\S+)\s+([0-9\/\-+]+)\s+(\d+)\s+(\d+)/)
        if (haproxyMatch) {
          const [, syslogTime, process, clientAddr, reqTime, frontend, backend, timers, status, bytes] = haproxyMatch
          return {
            timestamp: reqTime,
            level: parseInt(status) >= 400 ? 'ERROR' : 'INFO',
            message: `${clientAddr} ${frontend}/${backend} → ${status} (${bytes} bytes)`,
            formatted: line,
            metadata: { 
              source: 'haproxy', 
              format: 'syslog',
              syslogTime,
              process,
              clientAddr,
              frontend,
              backend,
              timers,
              status,
              bytes
            }
          }
        }
        
        // Simplified HAProxy format
        const haproxySimpleMatch = line.match(/^.*\s+(\S+:\d+)\s+.*\s+(\d+)\s+(\d+)\s*$/)
        if (haproxySimpleMatch) {
          const [, clientAddr, status, bytes] = haproxySimpleMatch
          return {
            timestamp: new Date().toISOString(),
            level: parseInt(status) >= 400 ? 'ERROR' : 'INFO',
            message: `${clientAddr} → ${status} (${bytes} bytes)`,
            formatted: line,
            metadata: { 
              source: 'haproxy', 
              format: 'simple',
              clientAddr,
              status,
              bytes
            }
          }
        }
      } else if (proxyType === 'zoraxy') {
        // Zoraxy log format (experimental - basic parsing)
        const zoraxyMatch = line.match(/^(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})\s+(.+)/)
        if (zoraxyMatch) {
          const [, timestamp, message] = zoraxyMatch
          return {
            timestamp,
            level: message.toLowerCase().includes('error') ? 'ERROR' : 'INFO',
            message,
            formatted: line,
            metadata: { 
              source: 'zoraxy', 
              format: 'basic'
            }
          }
        }
      }
    }

    // Enhanced fallback parsing for generic log formats
    // Try to extract timestamp and level from common patterns
    const genericTimestampMatch = line.match(/^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+(?:\[?(\w+)\]?\s+)?(.+)$/)
    if (genericTimestampMatch) {
      const [, timestamp, level, message] = genericTimestampMatch
      return {
        timestamp,
        level: level?.toUpperCase(),
        message,
        formatted: line,
        metadata: { source: 'generic', format: 'timestamped' }
      }
    }

    // Final fallback: treat as plain text
    return {
      message: line,
      formatted: line,
      metadata: { source: 'unknown', format: 'plain' }
    }
  }

  const getLogLines = () => {
    const logs = getCurrentLogs()
    if (!logs) return []
    
    return logs.split('\n')
      .filter(line => line.trim())
      .map((line) => formatLogLine(line))
  }

  const getLevelColor = (level?: string) => {
    if (!level) return 'text-muted-foreground'
    
    switch (level.toUpperCase()) {
      case 'ERROR':
      case 'FATAL':
        return 'text-red-600'
      case 'WARN':
      case 'WARNING':
        return 'text-yellow-600'
      case 'INFO':
        return 'text-blue-600'
      case 'DEBUG':
        return 'text-gray-500'
      default:
        return 'text-muted-foreground'
    }
  }

  const getLevelBadge = (level?: string) => {
    if (!level) return null
    
    const variant = level.toUpperCase() === 'ERROR' || level.toUpperCase() === 'FATAL' 
      ? 'destructive' 
      : level.toUpperCase() === 'WARN' || level.toUpperCase() === 'WARNING'
      ? 'secondary'
      : 'outline'
    
    return (
      <Badge variant={variant} className="text-xs font-mono">
        {level}
      </Badge>
    )
  }

  const handleCopyLogs = async () => {
    const logs = getCurrentLogs()
    if (logs) {
      await navigator.clipboard.writeText(logs)
      toast.success('Logs copied to clipboard')
    }
  }

  const handleDownloadLogs = () => {
    const logs = getCurrentLogs()
    if (logs) {
      const blob = new Blob([logs], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${logType}-logs-${new Date().toISOString().split('T')[0]}.txt`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      toast.success('Logs downloaded')
    }
  }

  const logLines = getLogLines()
  const proxyName = proxyType.charAt(0).toUpperCase() + proxyType.slice(1)

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              {logType === 'crowdsec' ? 'CrowdSec Logs' : `${proxyName} Logs`}
            </CardTitle>
            <CardDescription>
              {logType === 'crowdsec' 
                ? 'Security events and decisions from CrowdSec engine'
                : `Access logs and events from ${proxyName} reverse proxy`
              }
            </CardDescription>
          </div>
          
          <div className="flex items-center gap-2">
            <Badge variant="outline">
              {tailLines} lines
            </Badge>
            {isLoading && (
              <Badge variant="secondary">
                <Activity className="h-3 w-3 mr-1 animate-spin" />
                Loading
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="space-y-4">
        {/* Controls */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowTimestamps(!showTimestamps)}
            >
              {showTimestamps ? <EyeOff className="h-4 w-4 mr-2" /> : <Eye className="h-4 w-4 mr-2" />}
              Timestamps
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setWrapLines(!wrapLines)}
            >
              {wrapLines ? 'No Wrap' : 'Wrap Lines'}
            </Button>
          </div>
          
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleCopyLogs}
              disabled={!getCurrentLogs()}
            >
              <Copy className="h-4 w-4 mr-2" />
              Copy
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleDownloadLogs}
              disabled={!getCurrentLogs()}
            >
              <Download className="h-4 w-4 mr-2" />
              Download
            </Button>
          </div>
        </div>

        {/* Log Content */}
        {logType === 'proxy' && !supportsLogs ? (
          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              {proxyName} does not support log parsing. Only CrowdSec logs are available for this proxy type.
            </AlertDescription>
          </Alert>
        ) : isLoading ? (
          <div className="flex items-center justify-center p-8">
            <Activity className="h-6 w-6 animate-spin mr-2" />
            <span>Loading logs...</span>
          </div>
        ) : logLines.length === 0 ? (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              No log entries found. This could mean:
              <ul className="list-disc list-inside mt-2 space-y-1">
                <li>The service hasn't generated any logs yet</li>
                <li>Log files are not accessible</li>
                <li>The service is not running</li>
              </ul>
            </AlertDescription>
          </Alert>
        ) : (
          <div className="border rounded-lg">
            <ScrollArea className="h-96">
              <div className="p-4 font-mono text-sm space-y-1">
                {logLines.map((logLine, index) => (
                  <div 
                    key={index} 
                    className={`group flex items-start gap-3 py-2 px-2 hover:bg-muted/50 rounded-sm ${
                      wrapLines ? 'flex-wrap' : ''
                    }`}
                  >
                    {showTimestamps && logLine.timestamp && (
                      <div className="flex items-center gap-2 text-xs text-muted-foreground min-w-0 flex-shrink-0">
                        <Clock className="h-3 w-3" />
                        <span className="font-mono">
                          {new Date(logLine.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                    )}
                    
                    {logLine.level && (
                      <div className="flex-shrink-0">
                        {getLevelBadge(logLine.level)}
                      </div>
                    )}
                    
                    {/* Source indicator */}
                    {logLine.metadata?.source && (
                      <div className="flex-shrink-0">
                        <Badge variant="outline" className="text-xs">
                          {logLine.metadata.source}
                        </Badge>
                      </div>
                    )}
                    
                    <div className={`flex-1 min-w-0 ${wrapLines ? 'break-all' : 'truncate'}`}>
                      <span className={logLine.level ? getLevelColor(logLine.level) : 'text-foreground'}>
                        {logLine.message || logLine.formatted}
                      </span>
                      
                      {/* Enhanced metadata display */}
                      {logLine.metadata && Object.keys(logLine.metadata).length > 1 && (
                        <div className="mt-1 opacity-0 group-hover:opacity-100 transition-opacity">
                          <div className="flex flex-wrap gap-1">
                            {logLine.metadata.status && (
                              <Badge variant="outline" className="text-xs">
                                {logLine.metadata.status}
                              </Badge>
                            )}
                            {logLine.metadata.method && (
                              <Badge variant="outline" className="text-xs">
                                {logLine.metadata.method}
                              </Badge>
                            )}
                            {logLine.metadata.ip && (
                              <Badge variant="outline" className="text-xs font-mono">
                                {logLine.metadata.ip}
                              </Badge>
                            )}
                            {logLine.metadata.duration && (
                              <Badge variant="outline" className="text-xs">
                                {logLine.metadata.duration}
                              </Badge>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </div>
        )}

        {/* Log Stats */}
        {logLines.length > 0 && (
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <div className="flex items-center gap-4">
              <span>Total lines: {logLines.length}</span>
              {logLines.some(l => l.level === 'ERROR') && (
                <span className="text-red-600">
                  Errors: {logLines.filter(l => l.level === 'ERROR').length}
                </span>
              )}
              {logLines.some(l => l.level === 'WARN' || l.level === 'WARNING') && (
                <span className="text-yellow-600">
                  Warnings: {logLines.filter(l => l.level === 'WARN' || l.level === 'WARNING').length}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-500" />
              <span>Last updated: {new Date().toLocaleTimeString()}</span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}