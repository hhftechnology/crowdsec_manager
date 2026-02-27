import axios from 'axios'

type APIErrorResponse = {
  error?: string
  message?: string
}

export const ErrorContexts = {
  WhitelistCurrentAdd: 'whitelist.current.add',
  WhitelistManualAdd: 'whitelist.manual.add',
  WhitelistCIDRAdd: 'whitelist.cidr.add',
  WhitelistComprehensiveSetup: 'whitelist.comprehensive.setup',
  WhitelistRemove: 'whitelist.remove',
  UpdateWithCrowdSec: 'update.with_crowdsec',
  UpdateWithoutCrowdSec: 'update.without_crowdsec',
  ServicesActionStart: 'services.action.start',
  ServicesActionStop: 'services.action.stop',
  ServicesActionRestart: 'services.action.restart',
  ServicesShutdown: 'services.shutdown',
  CronCreate: 'cron.create',
  CronDelete: 'cron.delete',
  ScenariosSetup: 'scenarios.setup',
  ScenariosSimulationModeUpdate: 'scenarios.simulation_mode.update',
  ConfigSnapshotAll: 'config.snapshot_all',
  ConfigRestore: 'config.restore',
  ConfigAccept: 'config.accept',
  ConfigSnapshotDelete: 'config.snapshot.delete',
  ProfilesLoadDefault: 'profiles.load_default',
  ProfilesSave: 'profiles.save',
  BackupCreate: 'backup.create',
  BackupRestore: 'backup.restore',
  BackupDelete: 'backup.delete',
  BackupCleanup: 'backup.cleanup',
  NotificationsLoad: 'notifications.load',
  NotificationsPreview: 'notifications.preview',
  NotificationsSave: 'notifications.save',
  TraefikConfigPathUpdate: 'traefik.config_path.update',
  CaptchaSetup: 'captcha.setup',
  LogsStreamConnect: 'logs.stream.connect',
  LogsStreamWebsocketError: 'logs.stream.websocket_error',
  HubInstall: 'hub.install',
  HubRemove: 'hub.remove',
  HubUpgradeAll: 'hub.upgrade_all',
  IPCheckBlocked: 'ip.check_blocked',
  IPCheckSecurity: 'ip.check_security',
  IPUnban: 'ip.unban',
  EnrollSubmitKey: 'enroll.submit_key',
} as const

export type ErrorContext = typeof ErrorContexts[keyof typeof ErrorContexts]

type ErrorRule = {
  contexts: ErrorContext[] | 'any'
  patterns: RegExp[]
  message: string
}

const ERROR_RULES: ErrorRule[] = [
  {
    contexts: [
      ErrorContexts.WhitelistManualAdd,
      ErrorContexts.WhitelistCIDRAdd,
      ErrorContexts.WhitelistComprehensiveSetup,
      ErrorContexts.WhitelistRemove,
      ErrorContexts.CaptchaSetup,
      ErrorContexts.TraefikConfigPathUpdate,
    ],
    patterns: [/mounted volume is marked read-only/i, /read-only file system/i],
    message: 'The Traefik config volume is read-only. Make it writable and retry.',
  },
  {
    contexts: [
      ErrorContexts.WhitelistManualAdd,
      ErrorContexts.WhitelistCIDRAdd,
      ErrorContexts.WhitelistComprehensiveSetup,
      ErrorContexts.WhitelistRemove,
      ErrorContexts.CaptchaSetup,
    ],
    patterns: [/no such file or directory/i, /stat .* no such file or directory/i],
    message: 'Traefik dynamic config file not found. Verify the config path in Settings.',
  },
  {
    contexts: 'any',
    patterns: [/no such container/i, /container .* is not running/i],
    message: 'Target container is not running. Start it in Services and try again.',
  },
  {
    contexts: 'any',
    patterns: [/permission denied/i],
    message: 'Permission denied. Check container volume permissions and retry.',
  },
  {
    contexts: 'any',
    patterns: [/context deadline exceeded/i, /\btimeout\b/i],
    message: 'Operation timed out. Please try again.',
  },
  {
    contexts: 'any',
    patterns: [/connection refused/i],
    message: 'Connection refused. Ensure the target service is running.',
  },
]

function extractRawMessage(error: unknown): string | null {
  if (typeof error === 'string' && error.trim()) return error
  if (error instanceof Error && error.message) return error.message

  if (axios.isAxiosError(error)) {
    const responseData = error.response?.data as APIErrorResponse | undefined
    if (responseData?.error) return responseData.error
    if (responseData?.message) return responseData.message
  }

  return null
}

function mapErrorMessage(context: ErrorContext, rawMessage: string): string | null {
  for (const rule of ERROR_RULES) {
    if (rule.contexts !== 'any' && !rule.contexts.includes(context)) continue
    if (rule.patterns.some((pattern) => pattern.test(rawMessage))) {
      return rule.message
    }
  }
  return null
}

export function getErrorMessage(error: unknown, fallback: string, context?: ErrorContext): string {
  const rawMessage = extractRawMessage(error)
  if (context && rawMessage) {
    const mapped = mapErrorMessage(context, rawMessage)
    if (mapped) return mapped
  }
  if (rawMessage) return rawMessage
  return fallback
}
