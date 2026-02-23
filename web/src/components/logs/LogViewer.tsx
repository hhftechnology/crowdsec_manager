import { useEffect, useRef, useState, useCallback } from 'react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Check, Copy, ArrowDownToLine } from 'lucide-react'

interface LogViewerProps {
  logs: string[]
  maxLines?: number
  autoScroll?: boolean
  className?: string
}

function LogViewer({
  logs,
  maxLines = 1000,
  autoScroll = true,
  className,
}: LogViewerProps) {
  const scrollRef = useRef<HTMLDivElement>(null)
  const [isAutoScrollEnabled, setIsAutoScrollEnabled] = useState(autoScroll)
  const [copied, setCopied] = useState(false)

  const displayedLogs = maxLines > 0 ? logs.slice(-maxLines) : logs

  useEffect(() => {
    if (isAutoScrollEnabled && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [displayedLogs, isAutoScrollEnabled])

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(displayedLogs.join('\n'))
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard API not available
    }
  }, [displayedLogs])

  return (
    <div className={cn('relative rounded-md border bg-zinc-950', className)}>
      {/* Toolbar */}
      <div className="flex items-center justify-between border-b border-zinc-800 px-3 py-2">
        <span className="text-xs text-zinc-400">
          {displayedLogs.length} line{displayedLogs.length !== 1 ? 's' : ''}
        </span>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            className="h-7 gap-1 text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
            onClick={() => setIsAutoScrollEnabled(!isAutoScrollEnabled)}
          >
            <ArrowDownToLine className="h-3 w-3" />
            {isAutoScrollEnabled ? 'Auto-scroll on' : 'Auto-scroll off'}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 gap-1 text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
            onClick={handleCopy}
          >
            {copied ? (
              <Check className="h-3 w-3" />
            ) : (
              <Copy className="h-3 w-3" />
            )}
            {copied ? 'Copied' : 'Copy'}
          </Button>
        </div>
      </div>

      {/* Log content */}
      <ScrollArea className="h-[400px]">
        <div ref={scrollRef} className="h-full overflow-auto p-3">
          {displayedLogs.length === 0 ? (
            <p className="text-center text-sm text-zinc-500">No logs to display</p>
          ) : (
            <pre className="font-mono text-xs leading-relaxed text-zinc-300 whitespace-pre-wrap break-all">
              {displayedLogs.map((line, i) => (
                <div key={i} className="hover:bg-zinc-800/50 px-1 -mx-1 rounded">
                  {line}
                </div>
              ))}
            </pre>
          )}
        </div>
      </ScrollArea>
    </div>
  )
}

export { LogViewer }
export type { LogViewerProps }
