export type ConnectionMode = 'direct' | 'proxy-basic' | 'pangolin';

export interface ConnectionProfile {
  mode: ConnectionMode;
  baseUrl: string;
  allowInsecure: boolean;
  proxyUsername: string;
  proxyPassword: string;
  pangolinToken: string;
  pangolinTokenParam: string;
}

export type ConnectionProfileDraft = ConnectionProfile;

export const DEFAULT_PANGOLIN_TOKEN_PARAM = 'p_token';

export interface PangolinAccessTokenParts {
  id: string;
  token: string;
  combined: string;
}

export function createDefaultConnectionProfileDraft(): ConnectionProfileDraft {
  return {
    mode: 'direct',
    baseUrl: '',
    allowInsecure: false,
    proxyUsername: '',
    proxyPassword: '',
    pangolinToken: '',
    pangolinTokenParam: DEFAULT_PANGOLIN_TOKEN_PARAM,
  };
}

export function normalizeConnectionProfileDraft(
  draft: Partial<ConnectionProfileDraft> | null | undefined,
): ConnectionProfileDraft {
  const defaults = createDefaultConnectionProfileDraft();

  return {
    mode: normalizeMode(draft?.mode),
    baseUrl: normalizeUrlInput(draft?.baseUrl ?? defaults.baseUrl),
    allowInsecure: Boolean(draft?.allowInsecure),
    proxyUsername: (draft?.proxyUsername ?? defaults.proxyUsername).trim(),
    proxyPassword: (draft?.proxyPassword ?? defaults.proxyPassword).trim(),
    pangolinToken: (draft?.pangolinToken ?? defaults.pangolinToken).trim(),
    pangolinTokenParam: normalizeTokenParam(draft?.pangolinTokenParam),
  };
}

export function finalizeConnectionProfile(
  draft: Partial<ConnectionProfileDraft>,
  resolvedBaseUrl: string,
): ConnectionProfile {
  const normalized = normalizeConnectionProfileDraft(draft);

  return {
    ...normalized,
    baseUrl: normalizeUrlInput(resolvedBaseUrl),
  };
}

export function isConnectionDraftComplete(draft: Partial<ConnectionProfileDraft>): boolean {
  const normalized = normalizeConnectionProfileDraft(draft);

  if (!normalized.baseUrl) return false;

  if (normalized.mode === 'proxy-basic') {
    return Boolean(normalized.proxyUsername && normalized.proxyPassword);
  }

  if (normalized.mode === 'pangolin') {
    return Boolean(parsePangolinAccessToken(normalized.pangolinToken));
  }

  return true;
}

export function parsePangolinAccessToken(value: string): PangolinAccessTokenParts | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  const splitIndex = trimmed.indexOf('.');
  if (splitIndex <= 0 || splitIndex === trimmed.length - 1) {
    return null;
  }

  const id = trimmed.slice(0, splitIndex).trim();
  const token = trimmed.slice(splitIndex + 1).trim();
  if (!id || !token) {
    return null;
  }

  return {
    id,
    token,
    combined: `${id}.${token}`,
  };
}

export function hasExplicitScheme(value: string): boolean {
  return /^[a-zA-Z][a-zA-Z\d+.-]*:\/\//.test(value.trim());
}

export function isExplicitHttpUrl(value: string): boolean {
  return value.trim().toLowerCase().startsWith('http://');
}

export function buildConnectionCandidates(rawUrl: string, allowInsecure: boolean): string[] {
  const normalized = normalizeUrlInput(rawUrl);
  if (!normalized) return [];

  const candidates = hasExplicitScheme(normalized)
    ? [normalized]
    : [`https://${normalized}`, ...(allowInsecure ? [`http://${normalized}`] : [])];

  return Array.from(
    new Set(
      candidates
        .map((candidate) => normalizeAbsoluteUrl(candidate))
        .filter((candidate): candidate is string => Boolean(candidate)),
    ),
  );
}

export function parseStoredConnectionProfile(value: string | null): ConnectionProfile | null {
  if (!value) return null;

  try {
    const parsed = JSON.parse(value) as Partial<ConnectionProfileDraft>;
    const normalized = normalizeConnectionProfileDraft(parsed);
    if (!normalized.baseUrl) return null;
    return normalized;
  } catch {
    return null;
  }
}

export function stripSensitiveConnectionFields(
  profile: ConnectionProfile,
): ConnectionProfile {
  const normalized = normalizeConnectionProfileDraft(profile);

  return {
    ...normalized,
    proxyPassword: '',
    pangolinToken: '',
  };
}

export function canAutoRestoreConnectionProfile(
  profile: ConnectionProfile,
): boolean {
  const normalized = normalizeConnectionProfileDraft(profile);

  if (normalized.mode === 'proxy-basic') {
    return Boolean(normalized.baseUrl && normalized.proxyPassword);
  }

  if (normalized.mode === 'pangolin') {
    return Boolean(
      normalized.baseUrl &&
        parsePangolinAccessToken(normalized.pangolinToken),
    );
  }

  return Boolean(normalized.baseUrl);
}

export function serializeConnectionProfile(profile: ConnectionProfile): string {
  return JSON.stringify(normalizeConnectionProfileDraft(profile));
}

export function normalizeUrlInput(value: string): string {
  return value.trim().replace(/\/+$/, '');
}

function normalizeAbsoluteUrl(value: string): string | null {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    return parsed.toString().replace(/\/+$/, '');
  } catch {
    return null;
  }
}

function normalizeMode(mode: ConnectionProfileDraft['mode'] | undefined): ConnectionMode {
  if (mode === 'proxy-basic' || mode === 'pangolin') {
    return mode;
  }

  return 'direct';
}

function normalizeTokenParam(value: string | undefined): string {
  const trimmed = value?.trim();
  return trimmed || DEFAULT_PANGOLIN_TOKEN_PARAM;
}
