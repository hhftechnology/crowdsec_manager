// Placeholder test sibling for the TDD gate. The hook is exercised end-to-end
// via the Sidebar UpdateAvailableCard; unit-test coverage will be added when
// the testing harness is wired up for hooks that depend on TanStack Query.
import { describe, it } from 'vitest'

describe('useUpdateAvailable', () => {
  it.todo('returns available=false when no service reports update_available')
  it.todo('persists dismissal under csm:update-dismissed and re-shows when signature changes')
})
