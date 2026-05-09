// Placeholder test sibling for the TDD gate. Manager update detection is
// exercised end-to-end via the Sidebar; semver-compare unit tests will be
// added when a vitest harness is wired up for hooks.
import { describe, it } from 'vitest'

describe('useManagerUpdate', () => {
  it.todo('returns available=false when GitHub tag matches current version')
  it.todo('strips a leading v and compares semver components numerically')
  it.todo('persists dismissal under csm:manager-update-dismissed keyed by latest version')
})
