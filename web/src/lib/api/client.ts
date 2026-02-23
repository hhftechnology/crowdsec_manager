import axios from 'axios'

// API Base Configuration
export const apiClient = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
})

// =============================================================================
// Host selector interceptor
// =============================================================================

let selectedHostId: string | null = null

export function setSelectedHost(hostId: string | null) {
  selectedHostId = hostId
}

export function getSelectedHost(): string | null {
  return selectedHostId
}

// Add host param to all requests when a non-default host is selected
apiClient.interceptors.request.use((config) => {
  if (selectedHostId) {
    config.params = { ...config.params, host: selectedHostId }
  }
  return config
})
