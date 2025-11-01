import { useEffect, useState } from 'react'
import { Badge } from './ui/badge'
import { Activity, Github, MessageCircle, Home } from 'lucide-react'
import { Button } from './ui/button'
import { useNavigate } from 'react-router-dom'

interface HeaderProps {
  onMenuToggle: () => void
}

export default function Header({ onMenuToggle }: HeaderProps) {
  const [lastUpdate, setLastUpdate] = useState<string>('')
  const navigate = useNavigate()

  useEffect(() => {
    const updateTime = () => {
      const now = new Date()
      const hours = now.getHours().toString().padStart(2, '0')
      const minutes = now.getMinutes().toString().padStart(2, '0')
      const seconds = now.getSeconds().toString().padStart(2, '0')
      setLastUpdate(`${hours}:${minutes}:${seconds}`)
    }

    updateTime()
    const interval = setInterval(updateTime, 1000)

    return () => clearInterval(interval)
  }, [])

  return (
    <header className="h-16 border-b border-border bg-card px-6 flex items-center justify-between">
      <div className="flex items-center gap-4">
        <Activity className="h-6 w-6 text-red-500" />
        <div>
          <h1 className="text-xl font-bold">CROWDSEC MANAGER</h1>
          <Badge variant="secondary" className="text-xs">
            Beta-version - v0.0.1
          </Badge>
        </div>
      </div>
      <div className="flex items-center gap-4">
        <span className="text-sm text-muted-foreground">
          Last update: {lastUpdate}
        </span>
        <Button
          variant="ghost"
          size="sm"
          className="gap-2"
          onClick={() => window.open('https://github.com/hhftechnology/crowdsec_manager', '_blank')}
        >
          <Github className="h-4 w-4" />
          GitHub
        </Button>
        <Button
          variant="ghost"
          size="sm"
          className="gap-2"
          onClick={() => window.open('https://discord.gg/xCtMFeUKf9', '_blank')}
        >
          <MessageCircle className="h-4 w-4" />
          Discord
        </Button>
        <Button
          variant="ghost"
          size="sm"
          className="gap-2"
          onClick={() => navigate('/')}
        >
          <Home className="h-4 w-4" />
          Home
        </Button>
      </div>
    </header>
  )
}
