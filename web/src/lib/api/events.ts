export const eventsAPI = {
  getWebSocketUrl: () => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${proto}//${window.location.host}/api/events/ws`
  },
}
