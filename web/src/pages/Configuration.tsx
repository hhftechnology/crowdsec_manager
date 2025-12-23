import { ValidationDashboard } from '@/components/settings/ValidationDashboard'
import { Settings } from 'lucide-react'

export default function Configuration() {
  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center gap-3">
        <Settings className="h-8 w-8" />
        <div>
          <h1 className="text-4xl font-bold">Settings & Configuration</h1>
          <p className="text-muted-foreground mt-1">
            Validate and manage your CrowdSec Manager configuration
          </p>
        </div>
      </div>

      <ValidationDashboard />
    </div>
  )
}
