import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'

import AreaTimeline from './AreaTimeline'

describe('mobile AreaTimeline', () => {
  it('renders without throwing for non-empty data', () => {
    const { container } = render(
      <AreaTimeline data={[{ date: 'a', value: 1 }, { date: 'b', value: 2 }]} />,
    )
    expect(container.querySelector('.recharts-responsive-container')).toBeTruthy()
  })

  it('renders gracefully for empty data', () => {
    const { container } = render(<AreaTimeline data={[]} />)
    expect(container.querySelector('.recharts-responsive-container')).toBeTruthy()
  })
})
