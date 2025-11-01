export default function Footer() {
  return (
    <footer className="border-t border-border bg-card px-6 py-3">
      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <div className="flex items-center gap-4">
          <span>CrowdSec Manager v1.0.0</span>
          <span>|</span>
          <span>Powered by CrowdSec</span>
        </div>
        <div className="flex items-center gap-4">
          <span>&copy; {new Date().getFullYear()} HHF Technology</span>
        </div>
      </div>
    </footer>
  )
}
