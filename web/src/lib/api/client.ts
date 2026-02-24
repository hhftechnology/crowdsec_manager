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

// =============================================================================
// Response error interceptor — normalise API envelope errors
// =============================================================================

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    // Extract the `error` field from the API envelope when available
    const apiError: string | undefined =
      error?.response?.data?.error
    if (apiError) {
      error.message = apiError
    }
    return Promise.reject(error)
  },
)
