import { useQuery } from '@tanstack/react-query'
import { ipAPI } from '@/lib/api'
import { Badge } from './ui/badge'
import { RefreshCw } from 'lucide-react'
import { Button } from './ui/button'
import { cn } from '@/lib/utils'

export default function Header() {
  const { data: publicIPData, refetch, isLoading } = useQuery({
    queryKey: ['publicIP'],
    queryFn: () => ipAPI.getPublicIP(),
  })

  return (
    <header className="h-16 border-b border-border bg-card px-6 flex items-center justify-between">
      <div className="flex items-center gap-4">
        <h2 className="text-lg font-semibold">CrowdSec Manager</h2>
      </div>
      <div className="flex items-center gap-4">
        {publicIPData?.data?.data?.ip && (
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Public IP:</span>
            <Badge variant="outline">{publicIPData.data.data.ip}</Badge>
          </div>
        )}
        <Button
          variant="ghost"
          size="icon"
          onClick={() => refetch()}
          disabled={isLoading}
        >
          <RefreshCw className={cn("h-4 w-4", isLoading && "animate-spin")} />
        </Button>
      </div>
    </header>
  )
}
