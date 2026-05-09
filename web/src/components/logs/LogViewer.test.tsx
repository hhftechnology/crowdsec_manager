import { describe, expect, it } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

import { LogViewer } from './LogViewer'

afterEach(() => cleanup())

describe('LogViewer', () => {
  it('shows the default empty message when no logs', () => {
    render(<LogViewer logs={[]} />)
    expect(screen.getByText(/No logs to display/i)).toBeTruthy()
  })

  it('honours emptyMessage override (used during streaming)', () => {
    render(<LogViewer logs={[]} emptyMessage="Stream connected — waiting for new lines…" />)
    expect(screen.getByText(/Stream connected/)).toBeTruthy()
  })

  it('renders log lines when present', () => {
    render(<LogViewer logs={['first line', 'second line']} />)
    expect(screen.getByText('first line')).toBeTruthy()
    expect(screen.getByText('second line')).toBeTruthy()
  })
})
