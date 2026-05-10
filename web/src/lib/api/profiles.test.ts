import { describe, expect, it } from 'vitest'

import { buildProfileUpdatePayload, encodeProfileContent } from './profiles'

function utf8Base64(content: string): string {
  return btoa(String.fromCharCode(...new TextEncoder().encode(content)))
}

describe('profiles API payloads', () => {
  it('encodes profile content as UTF-8 base64', () => {
    const content = 'filters:\n  - Alert.GetScope() == "Ip" && marker == "✓"\n'

    expect(encodeProfileContent(content)).toBe(utf8Base64(content))
  })

  it('builds the base64 update payload', () => {
    const content = 'name: default_ip_remediation\n'

    expect(buildProfileUpdatePayload(content, true)).toEqual({
      content_b64: encodeProfileContent(content),
      encoding: 'base64',
      restart: true,
    })
  })
})
