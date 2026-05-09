import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'

import PieBreakdown from './PieBreakdown'

describe('mobile PieBreakdown', () => {
  it('renders without throwing', () => {
    const { container } = render(<PieBreakdown data={[{ name: '200', value: 5 }]} />)
    expect(container.querySelector('.recharts-responsive-container')).toBeTruthy()
  })
})
