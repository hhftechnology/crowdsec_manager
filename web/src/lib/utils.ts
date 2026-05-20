import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}

export function formatDate(date: string | Date): string {
  return new Date(date).toLocaleString()
}

export function parseUserAgent(ua: string) {
  if (!ua) return { browser: 'Unknown', os: 'Unknown', cpu: 'Unknown', device: 'Unknown' }

  let browser = 'Unknown'
  let os = 'Unknown'
  let cpu = 'Unknown'
  let device = 'Unknown'

  if (ua.includes('Firefox/')) browser = 'Firefox ' + ua.split('Firefox/')[1].split(' ')[0]
  else if (ua.includes('Edg/')) browser = 'Edge ' + ua.split('Edg/')[1].split(' ')[0]
  else if (ua.includes('Chrome/')) browser = 'Chrome ' + ua.split('Chrome/')[1].split(' ')[0]
  else if (ua.includes('Safari/') && !ua.includes('Chrome')) browser = 'Safari ' + ua.split('Safari/')[1].split(' ')[0]

  if (ua.includes('Android')) {
    os = 'Android ' + (ua.match(/Android ([\d.]+)/)?.[1] || '')
  } else if (ua.includes('iPhone') || ua.includes('iPad')) {
    os = 'iOS ' + (ua.match(/OS ([\d_]+)/)?.[1]?.replace(/_/g, '.') || '')
    device = ua.includes('iPhone') ? 'iPhone' : 'iPad'
  } else if (ua.includes('Windows NT')) {
    const ver = ua.match(/Windows NT ([\d.]+)/)?.[1]
    os = ver === '10.0' ? 'Windows 10/11' : ver === '6.3' ? 'Windows 8.1' : ver === '6.2' ? 'Windows 8' : ver === '6.1' ? 'Windows 7' : 'Windows'
  } else if (ua.includes('Mac OS X')) {
    os = 'macOS ' + (ua.match(/Mac OS X ([\d_]+)/)?.[1]?.replace(/_/g, '.') || '')
  } else if (ua.includes('Linux')) {
    os = 'Linux'
  }

  if (ua.includes('arm_64') || ua.includes('aarch64') || ua.includes('arm64')) cpu = 'ARM 64-bit'
  else if (ua.includes('x86_64') || ua.includes('amd64')) cpu = 'x86 64-bit'
  else if (ua.includes('i386') || ua.includes('i686')) cpu = 'x86 32-bit'

  const deviceMatch = ua.match(/\(([^)]+)\)/)
  if (deviceMatch && device === 'Unknown') {
    const parts = deviceMatch[1].split(';')
    for (const part of parts) {
      const p = part.trim()
      if (p.includes('Android') || p.includes('Linux') || p.includes('Windows') || p.includes('Macintosh')) continue
      if (p.length > 2) {
        device = p
        break
      }
    }
  }

  return { browser, os, cpu, device }
}

function parseCLFTimestamp(value: string): string | null {
  const months: Record<string, number> = {
    Jan: 1,
    Feb: 2,
    Mar: 3,
    Apr: 4,
    May: 5,
    Jun: 6,
    Jul: 7,
    Aug: 8,
    Sep: 9,
    Oct: 10,
    Nov: 11,
    Dec: 12,
  }
  const match = value.match(/^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})$/)
  if (!match) {
    const parsed = Date.parse(value)
    return Number.isNaN(parsed) ? null : new Date(parsed).toISOString()
  }
  const [, day, monthName, year, hour, minute, second, offset] = match
  const month = months[monthName]
  if (!month) return null
  const isoLike = `${year}-${String(month).padStart(2, '0')}-${day}T${hour}:${minute}:${second}${offset.slice(0, 3)}:${offset.slice(3)}`
  const parsed = Date.parse(isoLike)
  return Number.isNaN(parsed) ? null : new Date(parsed).toISOString()
}

export function getMethodStyles(method: string) {
  switch (method?.toUpperCase()) {
    case 'GET': return 'bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/20'
    case 'POST': return 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/20'
    case 'PUT': return 'bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/20'
    case 'DELETE': return 'bg-rose-500/15 text-rose-700 dark:text-rose-400 border-rose-500/20'
    case 'PATCH': return 'bg-purple-500/15 text-purple-700 dark:text-purple-400 border-purple-500/20'
    default: return 'bg-muted text-muted-foreground border-transparent'
  }
}

export function getStatusVariant(status: number): 'success' | 'info' | 'warning' | 'destructive' | 'secondary' {
  if (status >= 200 && status < 300) return 'success'
  if (status >= 300 && status < 400) return 'info'
  if (status >= 400 && status < 500) return 'warning'
  if (status >= 500) return 'destructive'
  return 'secondary'
}

export function parseTraefikLog(line: string) {
  try {
    if (line.trim().startsWith('{')) {
      const d = JSON.parse(line)
      const rawDuration = d.Duration ?? d.duration
      const durationNumber = rawDuration == null || rawDuration === '' ? NaN : Number(rawDuration)
      const durationMs = Number.isFinite(durationNumber) ? durationNumber / 1_000_000 : undefined
      return {
        ...d,
        Duration: durationMs,
        t: d.StartLocal || d.StartUTC || d.time || d.t,
        ip: d.ClientHost || d.ClientAddr || d.client_ip || d.ip,
        method: d.RequestMethod || d.method,
        path: d.RequestPath || d.path,
        host: d.RequestHost || d.request_Host || d.host,
        ua: d.UserAgent || d["request_User-Agent"] || d.user_agent || d.ua,
        status: d.DownstreamStatus || d.status,
        duration: durationMs,
        service: d.ServiceName || d.service,
        msg: d.msg || d.message || line
      }
    }
    const clf = line.match(/^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) \S+" (\d+) (\d+)/)
    if (clf) {
      return { ip: clf[1], t: parseCLFTimestamp(clf[2]), method: clf[3], path: clf[4], status: parseInt(clf[5]), msg: line }
    }
  } catch (e) {}
  return { msg: line, t: null, ip: null, method: null, path: null, status: null }
}

export function groupStatusCodes(statusCodes: { name: string; value: number }[]) {
  if (!statusCodes) return []
  const groups: Record<string, number> = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 }
  statusCodes.forEach((c) => {
    const firstDigit = c.name.charAt(0)
    const groupName = `${firstDigit}xx`
    if (groups[groupName] !== undefined) {
      groups[groupName] += c.value
    }
  })
  return Object.entries(groups)
    .filter(([_, value]) => value > 0)
    .map(([name, value]) => {
      let fill = 'hsl(var(--muted))'
      if (name.startsWith('2')) fill = 'hsl(var(--success))'
      else if (name.startsWith('3')) fill = 'hsl(var(--info))'
      else if (name.startsWith('4')) fill = 'hsl(var(--warning))'
      else if (name.startsWith('5')) fill = 'hsl(var(--destructive))'
      return { name, value, fill }
    })
}
