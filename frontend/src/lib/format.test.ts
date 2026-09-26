import { describe, expect, it } from 'vitest'
import { bps, speed, typeLabel, uptime } from './format'

describe('format', () => {
  it('formats bit rates', () => {
    expect(bps(0)).toBe('0 bps')
    expect(bps(1500)).toBe('1.5 Kbps')
    expect(bps(10_000_000_000)).toBe('10.0 Gbps')
    expect(bps(null)).toBe('—')
  })
  it('formats port speeds', () => {
    expect(speed(1_000_000_000)).toBe('1G')
    expect(speed(100_000_000)).toBe('100M')
    expect(speed(0)).toBe('—')
  })
  it('labels device types', () => {
    expect(typeLabel('access_point')).toBe('Access point')
    expect(typeLabel(undefined)).toBe('Unknown')
  })
  it('formats uptime', () => {
    expect(uptime(90061)).toBe('1d 1h')
    expect(uptime(3660)).toBe('1h 1m')
  })
})
