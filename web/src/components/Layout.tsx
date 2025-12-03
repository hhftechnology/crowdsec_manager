import { ReactNode, useState } from 'react'
import Sidebar from './Sidebar'
import Header from './Header'

interface LayoutProps {
  children: ReactNode
}

export default function Layout({ children }: LayoutProps) {
  const [isCollapsed, setIsCollapsed] = useState(false)

  return (
    <div className="flex h-full bg-background overflow-hidden">
      <Sidebar isCollapsed={isCollapsed} setIsCollapsed={setIsCollapsed} />
      <div className="flex flex-col flex-1 overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto bg-background p-6">
          {children}
        </main>
        <footer className="border-t p-4 text-center text-xs text-muted-foreground bg-background">
          <p>&copy; {new Date().getFullYear()} HHF Technology</p>
          <p>Powered by CrowdSec (Only for Pangolin Users)</p>
          <p>CrowdSec Manager - Beta-version - v0.0.1</p>
        </footer>
      </div>
    </div>
  )
}
