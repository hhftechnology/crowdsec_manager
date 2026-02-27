export const terminalAPI = {
  getWebSocketUrl: (container: string) => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${proto}//${window.location.host}/api/terminal/${container}`
  },
}
