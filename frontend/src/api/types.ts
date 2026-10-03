export type UserRole = 'administrator' | 'read_only' | string;

export interface UserSummary {
  id: string;
  username: string;
  display_name: string;
  role: UserRole;
}

export interface ManagedUser extends UserSummary {
  is_active: boolean;
  last_login_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface SessionResponse {
  authenticated: boolean;
  user: UserSummary;
  csrf_token: string;
}

export interface SetupStatus {
  setup_required: boolean;
}

export interface DashboardMetrics {
  total_tracked_assets?: number;
  assets_with_open_medium?: number;
  assets_with_open_low?: number;
  open_findings_by_severity?: Record<string, number>;
  findings_inside_maturity_gate?: number;
  findings_outside_maturity_gate?: number;
  findings_approaching_sla?: number;
  overdue_findings?: number;
  findings_by_administrative_team?: Record<string, number> | Array<{ name: string; count: number }>;
  findings_by_maintenance_group?: Record<string, number> | Array<{ name: string; count: number }>;
  maturity?: Record<string, number>;
  sla?: Record<string, number>;
  recent_imports?: ImportRun[];
  unresolved_identity_review_items?: number;
  data_quality_warnings?: Array<Record<string, unknown> | string> | number;
}

export interface AssetSummary {
  id: string;
  canonical_hostname?: string | null;
  current_ip_addresses?: string[];
  known_aliases?: string[];
  operating_system?: string | null;
  system_owner?: string | null;
  owner?: string | null;
  administrative_team?: string | null;
  team?: string | null;
  environment?: string | null;
  maintenance_group?: string | null;
  medium_count?: number;
  low_count?: number;
  open_medium_count?: number;
  open_low_count?: number;
  mature_backlog_count?: number;
  new_deferred_count?: number;
  overdue_count?: number;
  oldest_open_finding?: string | null;
  last_scan_observed_at?: string | null;
  identity_confidence?: number | null;
  identity_review_state?: string | null;
  unresolved_identity?: boolean;
  tags?: Array<string | { id?: string; name: string }>;
}

export interface AssetDetail extends AssetSummary {
  identifiers?: AssetIdentifier[];
  historical_ip_addresses?: string[];
  technical_owner?: string | null;
  data_center?: string | null;
  business_service?: string | null;
  server_role?: string | null;
  patch_group?: string | null;
  notes?: string | null;
  findings?: FindingSummary[];
  import_history?: ImportRun[];
  identity_history?: Array<Record<string, unknown>>;
}

export interface AssetIdentifier {
  id: string;
  identifier_type?: string;
  type?: string;
  normalized_value: string;
  original_value?: string;
  first_observed_at?: string;
  last_observed_at?: string;
  confidence?: number;
  manually_verified?: boolean;
  active?: boolean;
  shared_or_non_identifying?: boolean;
}

export interface FindingSummary {
  id: string;
  asset_id?: string;
  canonical_hostname?: string | null;
  plugin_id: string;
  plugin_name?: string | null;
  plugin_family?: string | null;
  severity: string;
  cves?: string[];
  port?: number;
  protocol?: string;
  service?: string | null;
  status?: string;
  maturity_status?: string | null;
  sla_status?: string | null;
  first_found_at?: string | null;
  last_found_at?: string | null;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  days_overdue?: number | null;
  owner?: string | null;
  administrative_team?: string | null;
  environment?: string | null;
  exploit_available?: boolean | null;
}

export interface PluginSummary {
  plugin_id: string;
  plugin_name?: string | null;
  severity?: string;
  cves?: string[];
  solution?: string | null;
  affected_host_count?: number;
  affected_hosts?: Array<{ id: string; canonical_hostname?: string | null }>;
  owners?: string[];
  teams?: string[];
  first_observed_at?: string | null;
  last_observed_at?: string | null;
  maturity_distribution?: Record<string, number>;
  sla_distribution?: Record<string, number>;
}

export interface ImportRun {
  id: string;
  status: string;
  source_type?: string;
  original_filename?: string;
  file_hash?: string;
  requested_at?: string;
  completed_at?: string | null;
  progress?: number;
  total_records?: number;
  included_records?: number;
  skipped_records?: number;
  severity_counts?: Record<string, number>;
  unique_assets?: number;
  new_assets?: number;
  matched_assets?: number;
  ambiguous_assets?: number;
  new_findings?: number;
  updated_findings?: number;
  parse_warnings?: unknown[];
  mapping_warnings?: unknown[];
  duplicate?: boolean;
  duplicate_of_import_id?: string | null;
  source_file?: {
    id: string;
    original_filename: string;
    sha256: string;
    content_type?: string | null;
    byte_size?: number;
    uploaded_at?: string;
  };
  job?: {
    status: string;
    progress: number;
    attempts?: number;
    error_message?: string | null;
  };
  identity_review_items?: number;
}

export interface IdentityReviewItem {
  id: string;
  status: string;
  incoming_identifiers?: Array<Record<string, unknown>>;
  candidate_asset_ids?: string[];
  candidate_assets?: AssetSummary[];
  conflicting_evidence?: Array<Record<string, unknown>>;
  matching_rule?: string;
  explanation?: string;
  confidence?: number;
  source_import_id?: string;
  first_observed_at?: string | null;
  last_observed_at?: string | null;
}

export interface SavedView {
  id: string;
  name: string;
  description?: string | null;
  shared: boolean;
  query_schema_version: number;
  query_json?: HostQuery;
  query?: HostQuery;
  revision: number;
  updated_at?: string;
}

export type SortDirection = 'asc' | 'desc';

export interface HostQuery {
  schema_version?: 1;
  q?: string;
  canonical_hostnames?: string[];
  aliases?: string[];
  ip_addresses?: string[];
  ip_scope?: 'current' | 'history' | 'both';
  operating_systems?: string[];
  system_owners?: string[];
  administrative_teams?: string[];
  environments?: string[];
  data_centers?: string[];
  maintenance_groups?: string[];
  tags?: { values: string[]; match: 'any' | 'all' };
  identity_review_state?: 'include_unresolved' | 'exclude_unresolved' | 'only_unresolved';
  open_severities?: string[];
  maturity_states?: string[];
  sla_states?: string[];
  plugin_ids?: string[];
  cves?: string[];
  sort?: Array<{ field: string; direction: SortDirection }>;
}

export interface FindingScope {
  schema_version?: 1;
  severities: string[];
  maturity_states?: string[];
  sla_states?: string[];
  statuses?: string[];
  plugin_ids?: string[];
  cves?: string[];
  exploit_indicator?: boolean;
}

export interface QueryPreview {
  normalized_query: HostQuery;
  matching_host_count: number;
  matching_finding_count?: number;
  estimated_matching_finding_count?: number;
  sample_hosts?: AssetSummary[];
  warnings?: Array<string | { code?: string; message?: string }>;
}

export interface ExportJob {
  id: string;
  status: string;
  progress?: number;
  scope_mode: 'selected_assets' | 'host_query' | 'saved_view';
  output_format: 'xlsx' | 'csv' | 'html' | 'pdf' | string;
  matched_host_count?: number;
  matched_finding_count?: number;
  data_as_of?: string;
  requested_at?: string;
  completed_at?: string | null;
  expires_at?: string | null;
  failure_reason?: string | null;
  output_sha256?: string | null;
  saved_view_name?: string | null;
  download_ready?: boolean;
}

export interface AuditEvent {
  id: string;
  occurred_at: string;
  actor?: string | null;
  actor_username?: string | null;
  event_type: string;
  entity_type?: string | null;
  entity_id?: string | null;
  outcome?: string;
  details?: Record<string, unknown>;
}

export interface AppSetting {
  id?: string;
  key: string;
  value: unknown;
  description?: string | null;
}
