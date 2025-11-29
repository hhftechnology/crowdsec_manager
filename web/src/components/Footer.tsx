export default function Footer() {
  return (
    <footer className="border-t border-border bg-card px-6 py-3">
      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <div className="flex items-center gap-4">
          <span>CrowdSec Manager- Beta-version - v0.0.1 | Powered by CrowdSec(Only for Pangolin Users)</span>
        </div>
        <div className="flex items-center gap-4">
          <span>&copy; {new Date().getFullYear()} HHF Technology</span>
        </div>
      </div>
    </footer>
  )
}
