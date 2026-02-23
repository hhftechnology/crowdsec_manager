import { useState, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import '@xterm/xterm/css/xterm.css'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { healthAPI } from '@/lib/api'
import { useTerminal } from '@/hooks/useTerminal'
import { TerminalSquare, Play, Square } from 'lucide-react'

export default function Terminal() {
  const [selectedContainer, setSelectedContainer] = useState('')

  const { data: healthData } = useQuery({
    queryKey: ['stack-health'],
    queryFn: () => healthAPI.checkStack(),
    refetchInterval: 10000,
  })

  const containers = healthData?.data?.data?.containers ?? []
  const runningContainers = containers.filter((c) => c.running)

  const handleConnect = useCallback(() => {
    toast.success('Terminal connected')
  }, [])

  const handleDisconnect = useCallback(() => {
    toast.info('Terminal disconnected')
  }, [])

  const handleError = useCallback((error: string) => {
    toast.error(error)
  }, [])

  const { terminalRef, connected, connect, disconnect } = useTerminal({
    container: selectedContainer,
    onConnect: handleConnect,
    onDisconnect: handleDisconnect,
    onError: handleError,
  })

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Terminal</h1>
        <p className="text-muted-foreground">Interactive container terminal sessions</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <TerminalSquare className="h-5 w-5" />
                Container Shell
              </CardTitle>
              <CardDescription>Connect to a running container's shell</CardDescription>
            </div>
            <Badge variant={connected ? 'default' : 'secondary'}>
              {connected ? 'Connected' : 'Disconnected'}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <Select value={selectedContainer} onValueChange={setSelectedContainer}>
              <SelectTrigger className="w-64">
                <SelectValue placeholder="Select container..." />
              </SelectTrigger>
              <SelectContent>
                {runningContainers.map((c) => (
                  <SelectItem key={c.name} value={c.name}>
                    <span className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full bg-green-500" />
                      {c.name}
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {!connected ? (
              <Button
                onClick={connect}
                disabled={!selectedContainer}
                className="gap-2"
              >
                <Play className="h-4 w-4" />
                Connect
              </Button>
            ) : (
              <Button
                onClick={disconnect}
                variant="destructive"
                className="gap-2"
              >
                <Square className="h-4 w-4" />
                Disconnect
              </Button>
            )}
          </div>

          {/* Terminal container */}
          <div
            ref={terminalRef}
            className="rounded-md border bg-[#1a1b26] min-h-[400px] p-1"
            style={{ height: 'calc(100vh - 380px)' }}
          />
        </CardContent>
      </Card>
    </div>
  )
}
