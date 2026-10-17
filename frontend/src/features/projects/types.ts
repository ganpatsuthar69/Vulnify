export type SupportedEcosystem = 'npm' | 'PyPI'

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

