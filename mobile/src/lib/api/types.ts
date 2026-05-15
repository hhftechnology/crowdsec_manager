export type {
  AddDecisionRequest,
  AlertFilters,
  AlertHistoryRecord,
  AlertHistoryResponse,
  AlertsResponse,
  ApiEnvelope,
  ApiResponse,
  BulkDeleteDecisionsRequest,
  BulkDeleteDecisionsResponse,
  BulkDeleteFailure,
  BulkReapplyDecisionsRequest,
  BulkReapplyResult,
  CrowdSecAlert as CrowdsecAlert,
  Decision,
  DecisionFilters,
  DecisionHistoryRecord,
  DecisionHistoryAnalysisResponse,
  DecisionHistoryResponse,
  DecisionsResponse,
  DeleteDecisionRequest,
  HistoryActivityBucket,
  HistoryActivityResponse,
  HistoryBreakdownItem,
  HistoryChartPoint,
  HistoryStats,
  ReapplyDecisionRequest,
  RepeatedOffender,
} from './contracts.generated';

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

export interface LogProcessingState {
  enabled: boolean;
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

export type DashboardRange = '5m' | '1h' | '6h' | '24h';

export const DASHBOARD_RANGES: DashboardRange[] = ['5m', '1h', '6h', '24h'];

export interface NameValue {
  name: string;
  value: number;
}

export interface IPStat {
  ip: string;
  count: number;
  country?: string;
  lat?: number;
  lng?: number;
}

export interface TraefikBucket {
  t: string;
  total: number;
  c2xx: number;
  c3xx: number;
  c4xx: number;
  c5xx: number;
}

export interface TraefikRecentError {
  t: string;
  ip: string;
  method?: string;
  path?: string;
  status: number;
  duration_ms?: number;
}

export interface TraefikDashboard {
  range: DashboardRange;
  format: 'json' | 'clf';
  generated_at: string;
  total_requests: number;
  unique_ips: number;
  avg_duration_ms: number | null;
  error_rate: number;
  series: TraefikBucket[];
  status_codes: NameValue[];
  methods: NameValue[];
  top_ips: IPStat[];
  top_hosts: NameValue[];
  top_routers: NameValue[];
  slowest_endpoints: NameValue[];
  tls_versions: NameValue[];
  recent_errors: TraefikRecentError[];
}

export interface CrowdSecBucket {
  t: string;
  alerts: number;
  decisions: number;
  errors: number;
}

export interface AcquisitionStat {
  source: string;
  lines: number;
}

export interface CrowdSecActivity {
  t: string;
  level: string;
  source?: string;
  message: string;
}

export interface CrowdSecDashboard {
  range: DashboardRange;
  generated_at: string;
  total_events: number;
  decisions: number;
  alerts: number;
  parser_errors: number;
  series: CrowdSecBucket[];
  top_scenarios: NameValue[];
  top_source_ips: IPStat[];
  top_origins: NameValue[];
  top_decision_types: NameValue[];
  acquisition: AcquisitionStat[];
  bouncer_activity: CrowdSecActivity[];
  recent_errors: CrowdSecActivity[];
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

export interface MetricsResponse {
  [key: string]: unknown;
}
