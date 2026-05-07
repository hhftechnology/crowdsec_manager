import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'

import BarDistribution from './BarDistribution'

describe('mobile BarDistribution', () => {
  it('renders both layouts without throwing', () => {
    const data = [
      { name: 'A', value: 1 },
      { name: 'B', value: 2 },
    ]
    const v = render(<BarDistribution data={data} />)
    expect(v.container.querySelector('.recharts-responsive-container')).toBeTruthy()
    v.unmount()
    const h = render(<BarDistribution data={data} layout="horizontal" />)
    expect(h.container.querySelector('.recharts-responsive-container')).toBeTruthy()
  })
})
