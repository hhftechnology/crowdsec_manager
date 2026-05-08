// Placeholder test sibling for the TDD gate. Card visual / interaction is
// exercised manually via the Sidebar; component tests will be added alongside
// a dedicated sidebar test suite.
import { describe, it } from 'vitest'

describe('ManagerUpdateCard', () => {
  it.todo('renders nothing when current version is up to date')
  it.todo('renders nothing when dismissed and latest version unchanged')
  it.todo('opens release_url in a new tab when View Release Notes is clicked')
})
