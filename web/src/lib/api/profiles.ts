import { apiClient } from './client'
import type { ApiResponse } from './types'

export type ProfileUpdatePayload = {
  content_b64: string
  encoding: 'base64'
  restart: boolean
}

export function encodeProfileContent(content: string): string {
  const bytes = new TextEncoder().encode(content)
  let binary = ''
  const chunkSize = 0x8000

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize))
  }

  return btoa(binary)
}

export function buildProfileUpdatePayload(content: string, restart: boolean): ProfileUpdatePayload {
  return {
    content_b64: encodeProfileContent(content),
    encoding: 'base64',
    restart,
  }
}

export const profilesAPI = {
  get: (useDefault?: boolean) =>
    apiClient.get<ApiResponse<string>>('/profiles', {
      params: useDefault ? { default: 'true' } : undefined,
    }),

  update: (content: string, restart: boolean) =>
    apiClient.post<ApiResponse<null>>('/profiles', buildProfileUpdatePayload(content, restart)),
}
