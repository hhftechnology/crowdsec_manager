export interface ApiEnvelope<T = unknown> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
}

export interface ApiResult<T> {
  data: T;
  message?: string;
}

export interface HealthContainer {
  name: string;
  id: string;
  status: string;
  running: boolean;
}

export interface StackHealth {
  containers: HealthContainer[];
  allRunning: boolean;
  timestamp: string;
}

export interface HealthCheckItem {
  status: string;
  message: string;
  error?: string;
  details?: string;
  metrics?: Record<string, unknown>;
}

export interface CrowdsecHealth {
  status: string;
  timestamp?: string;
  checks?: Record<string, HealthCheckItem>;
}

export interface DiagnosticResult {
  health: StackHealth | null;
  bouncers: Bouncer[];
  decisions: Decision[];
  traefik_integration?: Record<string, unknown>;
  timestamp: string;
}

export interface PublicIP {
  ip: string;
}

export interface IPBlockedStatus {
  ip: string;
  blocked: boolean;
  reason?: string;
}

export interface IPSecurity {
  ip: string;
  is_blocked: boolean;
  is_whitelisted: boolean;
  in_crowdsec: boolean;
  in_traefik: boolean;
}

export interface Decision {
  id: number;
  alert_id?: number;
  origin?: string;
  source?: string;
  type: string;
  scope?: string;
  value: string;
  duration?: string;
  scenario?: string;
  reason?: string;
  created_at?: string;
  until?: string;
}

export interface DecisionsResponse {
  decisions: Decision[];
  count: number;
  total?: number;
  limit?: number;
  offset?: number;
}

export interface AlertsResponse {
  alerts: CrowdsecAlert[];
  count: number;
}

export interface CrowdsecAlert {
  id: number;
  scenario?: string;
  scope?: string;
  value?: string;
  origin?: string;
  type?: string;
  message?: string;
  events_count?: number;
  start_at?: string;
  stop_at?: string;
  source?: {
    ip?: string;
    cn?: string;
    as_name?: string;
    scope?: string;
    value?: string;
  };
}

export interface AddDecisionRequest {
  ip?: string;
  range?: string;
  duration?: string;
  type?: string;
  scope?: string;
  value?: string;
  reason?: string;
}

export interface DeleteDecisionRequest {
  id?: string;
  ip?: string;
  range?: string;
  type?: string;
  scope?: string;
  value?: string;
  scenario?: string;
  origin?: string;
}

export interface Bouncer {
  name: string;
  ip_address: string;
  valid: boolean;
  last_pull: string;
  type: string;
  version?: string;
  status?: string;
}

export interface AllowlistEntry {
  value: string;
  expiration?: string;
  created_at?: string;
}

export interface Allowlist {
  name: string;
  description: string;
  created_at?: string;
  updated_at?: string;
  size?: number;
  items?: AllowlistEntry[];
}

export interface AllowlistInspectResponse {
  name: string;
  description: string;
  created_at?: string;
  updated_at?: string;
  items: AllowlistEntry[];
  count: number;
}

export interface ScenarioItem {
  name: string;
  status?: string;
  version?: string;
  local_version?: string;
  local_path?: string;
  description?: string;
  installed?: boolean;
}

export interface ScenarioListResponse {
  scenarios: ScenarioItem[];
  count: number;
}

export interface ScenarioFile {
  filename: string;
  name?: string;
  description?: string;
  type?: string;
  size?: number;
  modified?: string;
}

export interface ScenarioSetupPayload {
  scenarios: Array<{
    name: string;
    description: string;
    content: string;
  }>;
}

export interface StructuredLogEntry {
  timestamp: string;
  level: string;
  service: string;
  message: string;
}

export interface LogStats {
  total_lines: number;
  top_ips: Array<{ ip: string; count: number }>;
  status_codes: Record<string, number>;
  http_methods: Record<string, number>;
  error_entries: StructuredLogEntry[];
}

export interface StructuredLogsResponse {
  entries: StructuredLogEntry[];
  count: number;
  service: string;
}

export type HubCategoryKey =
  | 'collections'
  | 'scenarios'
  | 'parsers'
  | 'postoverflows'
  | 'remediations'
  | 'appsec-configs'
  | 'appsec-rules';

export interface HubCategory {
  key: HubCategoryKey;
  label: string;
  cli_type: string;
  container_dir: string;
  supports_direct: boolean;
}

export interface HubCategoryItem {
  name: string;
  status?: string;
  version?: string;
  local_version?: string;
  local_path?: string;
  description?: string;
  author?: string;
}

export interface HubCategoryItemsResponse {
  category: HubCategory;
  items?: HubCategoryItem[] | Record<string, unknown> | string;
  raw_output?: string;
}

export interface HubPreference {
  category: HubCategoryKey;
  default_mode: 'direct' | 'manual';
  default_yaml_path?: string;
  last_item_name?: string;
  updated_at?: string;
}

export interface HubOperationRecord {
  id: number;
  category: string;
  mode: string;
  action: string;
  item_name?: string;
  yaml_path?: string;
  command?: string;
  success: boolean;
  output?: string;
  error?: string;
  created_at?: string;
}

export interface DecisionHistoryRecord {
  id: number;
  dedupe_key: string;
  decision_id: number;
  alert_id: number;
  origin: string;
  type: string;
  scope: string;
  value: string;
  duration: string;
  scenario: string;
  created_at: string;
  until?: string;
  is_stale: boolean;
  first_seen_at: string;
  last_seen_at: string;
  stale_at?: string;
  last_snapshot_at: string;
}

export interface DecisionHistoryResponse {
  decisions: DecisionHistoryRecord[];
  count: number;
  total: number;
}

export interface ReapplyDecisionRequest {
  id: number;
  type: string;
  duration: string;
  reason?: string;
}

export interface MetricsResponse {
  [key: string]: unknown;
}

export interface HistoryActivityBucket {
  ts: string;
  alerts: number;
  decisions: number;
}

export interface HistoryActivityResponse {
  window: string;
  bucket: string;
  buckets: HistoryActivityBucket[];
  generated_at: string;
  latest_snapshot_at: string | null;
}
