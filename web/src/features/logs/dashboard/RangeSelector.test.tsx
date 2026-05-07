import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, fireEvent, cleanup } from '@testing-library/react'

import { RangeSelector } from './RangeSelector'

afterEach(() => cleanup())

describe('RangeSelector (sibling test)', () => {
  it('renders all four supported ranges', () => {
    const { getByRole } = render(<RangeSelector value="1h" onChange={() => {}} />)
    expect(getByRole('button', { name: '5m' })).toBeTruthy()
    expect(getByRole('button', { name: '1h' })).toBeTruthy()
    expect(getByRole('button', { name: '6h' })).toBeTruthy()
    expect(getByRole('button', { name: '24h' })).toBeTruthy()
  })

  it('invokes onChange with selected range', () => {
    const onChange = vi.fn()
    const { getByRole } = render(<RangeSelector value="1h" onChange={onChange} />)
    fireEvent.click(getByRole('button', { name: '24h' }))
    expect(onChange).toHaveBeenCalledWith('24h')
  })
})
