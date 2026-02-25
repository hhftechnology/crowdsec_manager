import { Link } from 'react-router-dom'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Package, ShieldAlert, ScanSearch, ArrowRight, Shield, AppWindow, ListChecks } from 'lucide-react'
import { PageHeader } from '@/components/common'

const cards = [
  {
    title: 'Collections',
    description: 'Collections group together multiple related Hub components.',
    href: '/hub/collections',
    icon: Package,
  },
  {
    title: 'Attack scenarios',
    description: 'YAML files that allow to detect a specific behavior and attacks.',
    href: '/hub/scenarios',
    icon: ShieldAlert,
  },
  {
    title: 'Log parsers',
    description: 'YAML configuration files that describe how logs must be parsed.',
    href: '/hub/parsers',
    icon: ScanSearch,
  },
  {
    title: 'Postoverflows',
    description: 'Parsers called when a scenario overflow occurs.',
    href: '/hub/postoverflows',
    icon: ListChecks,
  },
  {
    title: 'Remediation components',
    description: 'Standalone software pieces in charge of acting upon blocked IPs.',
    href: '/hub/remediations',
    icon: Shield,
  },
  {
    title: 'AppSec configurations',
    description: 'AppSec configs tie together AppSec rules and allow fine tuning.',
    href: '/hub/appsec-configs',
    icon: AppWindow,
  },
  {
    title: 'AppSec rules',
    description: 'AppSec rules allow the detection and blocking of malicious requests.',
    href: '/hub/appsec-rules',
    icon: ShieldAlert,
  },
]

export default function Hub() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Hub"
        description="Browse Hub categories and choose direct install or manual YAML mode"
        breadcrumbs="Hub / Home"
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">
        {cards.map((card) => {
          const Icon = card.icon
          return (
            <Link key={card.href} to={card.href}>
              <Card className="h-full transition-colors hover:border-primary/60">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Icon className="h-5 w-5 text-primary" />
                      <CardTitle className="text-xl">{card.title}</CardTitle>
                    </div>
                    <ArrowRight className="h-5 w-5 text-muted-foreground" />
                  </div>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-sm text-muted-foreground">
                    {card.description}
                  </CardDescription>
                </CardContent>
              </Card>
            </Link>
          )
        })}
      </div>
    </div>
  )
}
