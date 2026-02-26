import 'flag-icons/css/flag-icons.min.css'

const displayNames = new Intl.DisplayNames(['en'], { type: 'region' })

function getCountryName(code: string): string {
  try {
    return displayNames.of(code.toUpperCase()) || code.toUpperCase()
  } catch {
    return code.toUpperCase()
  }
}

export interface CountryFlagProps {
  code?: string | null
  showName?: boolean
  className?: string
}

export function CountryFlag({ code, showName = true, className = '' }: CountryFlagProps) {
  if (!code || code === 'Unknown' || code.length !== 2) {
    return <span className={`text-muted-foreground text-sm ${className}`}>-</span>
  }

  const lowerCode = code.toLowerCase()
  const name = getCountryName(code)

  return (
    <span className={`inline-flex items-center gap-1.5 ${className}`}>
      <span className={`fi fi-${lowerCode}`} title={name} />
      {showName && <span className="text-sm">{name}</span>}
    </span>
  )
}
