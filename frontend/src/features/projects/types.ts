export type SupportedEcosystem = 'npm' | 'PyPI' | 'Cargo' | 'Go' | string

export type FidelityLevel =
  | 'exact_lockfile'
  | 'checksum_verified'
  | 'transitive_resolved'
  | 'manifest_declared'
  | 'partial_resolution'

export interface ImportFieldDefinition {
  name: string
  label: string
  type: 'string' | 'file' | 'boolean' | 'select'
  required: boolean
  description: string
  placeholder?: string | null
  default_value?: unknown
  options?: string[] | null
}

export interface ImportMethodCapability {
  id: string
  name: string
  description: string
  fidelity: FidelityLevel
  fidelity_description: string
  accepted_filenames: string[]
  accepted_extensions: string[]
  requires_paired_file: boolean
  paired_file_name?: string | null
  paired_file_description?: string | null
  fields: ImportFieldDefinition[]
  limitations: string[]
}

export interface EcosystemCapability {
  id: string
  display_name: string
  osv_ecosystem: string
  supported_import_methods: ImportMethodCapability[]
  max_file_size_bytes: number
  max_packages: number
  validation_rules: string[]
  limitations: string[]
}

export interface EcosystemCapabilitiesResponse {
  supported_ecosystems: string[]
  capabilities: EcosystemCapability[]
}

export interface Project {
  id: string
  name: string
  ecosystem: SupportedEcosystem
  description?: string | null
  created_at: number
}

export interface ProjectCreateRequest {
  name: string
  ecosystem: SupportedEcosystem
  description?: string | null
}

export interface PackageVersion {
  id: string
  name: string
  version: string
  ecosystem: string
  purl: string
}

export type CreateProjectInput = ProjectCreateRequest

export interface ImportSummary {
  project_id: string
  service_name: string
  filename: string
  sha256_hash: string
  packages_parsed: int_number
  packages_created: int_number
  packages_reused: int_number
  edges_created: int_number
  edges_reused: int_number
  skipped_entries: int_number
  warnings: string[]
  errors: string[]
  status: 'completed' | 'partially_completed' | 'failed'
  imported_at: number
  fidelity?: string
  ecosystem?: string
  import_method?: string
  secondary_filename?: string | null
  job_id?: string | null
}

// Helper alias for clarity
type int_number = number

export type { ApiErrorPayload } from '@/shared/types/api'

export interface OsvImportSummary {
  project_id: string
  total_package_versions: number
  eligible_package_versions: number
  unique_lookups: number
  cache_hits: number
  advisories_found: number
  advisories_created: number
  advisories_updated: number
  relationships_created: number
  relationships_reused: number
  packages_with_no_advisories: number
  skipped_packages: number
  failed_lookups: number
  status: 'completed' | 'partial_failure' | 'failed' | 'skipped'
  errors: string[]
  duration_ms: number
  job_id?: string | null
}

export interface ProjectAdvisory {
  id: string
  summary: string
  details?: string
  severity: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'UNKNOWN' | string
  cvss?: string | null
  aliases: string[]
  published?: string | null
  modified?: string | null
  source_url?: string
  retrieved_at: number
  package_version_id: string
  package_name: string
  package_version: string
  ecosystem: string
}

export type MatchStatus = 'affected' | 'not_affected' | 'unknown'

export interface VersionMatchResult {
  package_name: string
  package_version: string
  ecosystem: string
  advisory_id: string
  status: MatchStatus
  reason_code: string
  reason: string
  matched_range?: string | null
  fixed_version?: string | null
  comparator: string
  evaluated_at: number
  fingerprint: string
}

export interface ProjectMatchResponse {
  project_id: string
  total_evaluated: number
  affected_count: number
  not_affected_count: number
  unknown_count: number
  relationships_persisted: number
  relationships_removed: number
  duration_ms: number
  status: 'completed' | 'partial_failure' | 'failed'
  results: VersionMatchResult[]
  job_id?: string | null
}

// US-105: Ingestion Jobs and History Types
export type JobStatus = 'queued' | 'running' | 'succeeded' | 'partial' | 'failed'

export type JobType = 'dependency_import' | 'osv_sync' | 'version_matching'

export interface IngestionJob {
  id: string
  project_id: string
  job_type: JobType | string
  status: JobStatus | string
  stage?: string | null
  service_id?: string | null
  service_name?: string | null
  processed_items: number
  total_items?: number | null
  percentage?: number | null
  discovered_items: number
  created_items: number
  updated_items: number
  reused_items: number
  skipped_items: number
  failed_items: number
  error_summary?: string | null
  errors: string[]
  warnings: string[]
  retry_eligible: boolean
  retry_of_job_id?: string | null
  created_at: number
  started_at?: number | null
  completed_at?: number | null
  duration_ms?: number | null
  initiated_by?: string | null
  filename?: string | null
  secondary_filename?: string | null
  sha256_hash?: string | null
  ecosystem?: string | null
  import_method?: string | null
  fidelity?: string | null
}

export interface IngestionJobSummaryStats {
  total_runs: number
  running_runs: number
  succeeded_runs: number
  failed_runs: number
  partial_runs: number
}

export interface IngestionJobListResponse {
  items: IngestionJob[]
  total: number
  page: number
  page_size: number
  total_pages: number
  summary_stats: IngestionJobSummaryStats
}

export interface JobRetryResponse {
  message: string
  original_job_id: string
  new_job: IngestionJob
}

export interface ListJobsFilterParams {
  page?: number
  page_size?: number
  status?: string
  job_type?: string
  service_name?: string
}

export interface VulnerabilityFinding {
  id: string
  summary: string
  details?: string
  severity: string
  cvss?: string | null
  aliases: string[]
  published?: string | null
  modified?: string | null
  source_url?: string
  package_version_id: string
  package_name: string
  package_version: string
  ecosystem: string
  match_status: MatchStatus | string
  match_reason: string
  reason_code: string
  matched_range?: string | null
  fixed_version?: string | null
  evaluated_at: number
  comparator: string
  fingerprint: string
}

