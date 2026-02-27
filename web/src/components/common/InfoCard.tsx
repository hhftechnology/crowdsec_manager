import type { ReactNode } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

interface InfoItem {
  label: string
  text: string
}

interface InfoCardProps {
  title: string
  description?: string
  items?: InfoItem[]
  children?: ReactNode
}

function InfoCard({ title, description, items, children }: InfoCardProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent className="space-y-2 text-sm text-muted-foreground">
        {items?.map((item, index) => (
          <p key={index}>
            <strong>{item.label}:</strong> {item.text}
          </p>
        ))}
        {children}
      </CardContent>
    </Card>
  )
}

export { InfoCard }
export type { InfoCardProps, InfoItem }
