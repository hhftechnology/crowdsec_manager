import { cn } from '@/lib/utils'
import { ProxyType, ProxyHealthData } from '@/lib/proxy-types'
import { StatusCard } from '@/components/common/StatusCard'
import {
  Network,
  Shield,
  Activity,
  Target,
} from 'lucide-react'

interface StatusDashboardProps {
  proxyType: ProxyType
  proxyStatus: {
    running: boolean
    connected: boolean
  }
  crowdsecStatus: {
    running: boolean
    enrolled: boolean
  }
  bouncerStatus: {
    connected: boolean
    lastSeen?: string
  }
  decisions: {
    count: number
    active: number
  }
  className?: string
}

export function StatusDashboard({
  proxyType,
  proxyStatus,
  crowdsecStatus,
  bouncerStatus,
  decisions,
  className
}: StatusDashboardProps) {
  const getProxyStatus = (): { status: 'success' | 'error' | 'warning', text: string } => {
    if (proxyStatus.running && proxyStatus.connected) return { status: 'success', text: 'Running' }
    if (proxyStatus.running && !proxyStatus.connected) return { status: 'warning', text: 'Disconnected' }
    return { status: 'error', text: 'Stopped' }
  }

  const getCrowdSecStatus = (): { status: 'success' | 'error' | 'warning', text: string } => {
    if (crowdsecStatus.running && crowdsecStatus.enrolled) return { status: 'success', text: 'Active' }
    if (crowdsecStatus.running && !crowdsecStatus.enrolled) return { status: 'warning', text: 'Not Enrolled' }
    return { status: 'error', text: 'Inactive' }
  }

  const getBouncerStatus = (): { status: 'success' | 'warning', text: string } => {
    return bouncerStatus.connected 
      ? { status: 'success', text: 'Connected' }
      : { status: 'warning', text: 'Disconnected' }
  }

  const proxyStatusData = getProxyStatus()
  const crowdsecStatusData = getCrowdSecStatus()
  const bouncerStatusData = getBouncerStatus()

  return (
    <div className={cn(
      "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4",
      className
    )}>
      <StatusCard
        title="Proxy Status"
        value={proxyStatusData.text}
        icon={Network}
        status={proxyStatusData.status}
        description={`${proxyType.charAt(0).toUpperCase() + proxyType.slice(1)} container`}
      />
      
      <StatusCard
        title="CrowdSec Status"
        value={crowdsecStatusData.text}
        icon={Shield}
        status={crowdsecStatusData.status}
        description="Security engine"
      />
      
      <StatusCard
        title="Bouncer Status"
        value={bouncerStatusData.text}
        icon={Activity}
        status={bouncerStatusData.status}
        description={bouncerStatus.lastSeen ? `Last seen: ${bouncerStatus.lastSeen}` : 'LAPI connection'}
      />
      
      <StatusCard
        title="Active Decisions"
        value={decisions.active}
        icon={Target}
        status="info"
        description={`${decisions.count} total decisions`}
      />
    </div>
  )
}