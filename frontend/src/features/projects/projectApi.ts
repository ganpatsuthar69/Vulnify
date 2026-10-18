import type {
  EcosystemCapabilitiesResponse,
  ImportSummary,
  Project,
  ProjectCreateRequest,
  OsvImportSummary,
  ProjectAdvisory,
  ProjectMatchResponse,
  VulnerabilityFinding,
  PackageVersion,
  IngestionJob,
  IngestionJobListResponse,
  JobRetryResponse,
  ListJobsFilterParams,
  FindingItem,
  FindingListResponse,
  ProjectService,
  FindingFilters,
  FindingSummaryResponse,
  FindingDetail,
  FindingPathsResponse,
  ProjectExposurePathsResponse,
  PathNode,
  PathEdge,
  ProjectDataQualityResponse,
  UpgradeCandidatesResponse,
  ProjectUpgradeCandidatesResponse,
  SimulationRequest,
  SimulationResponse,
  SimulationListResponse,
  GitHubIntegrationStatusResponse,
  GitHubConfigResponse,
  GitHubConfigUpdateRequest,
  GitHubConfigValidateRequest,
  GitHubValidationResult,
  GitHubIssuePreviewRequest,
  GitHubIssuePreviewResponse,
  GitHubIssueCreateRequest,
  GitHubIssueRecordResponse,
  GitHubIssueListResponse,
  TriageDecisionRequest,
  ReviewDecisionRequest,
  TriageDecisionResponse,
  ChangeComparisonResponse,
} from './types'
import { ApiClientError, isMockMode, parseApiError } from '@/shared/api/client'
import type { ApiClientErrorOptions } from '@/shared/types/api'
import { notifyUnauthorized } from '@/features/auth/authApi'
import type { ExplorerGraph, GraphRequest } from '@/features/graph/types'

export async function getProjectGraph(
  projectId: string,
  params: GraphRequest = {},
  signal?: AbortSignal,
): Promise<ExplorerGraph> {
  if (isMockMode()) {
    throw new ProjectApiError('The relationship explorer requires a live backend; sample edges are not generated.')
  }
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') query.set(key, String(value))
  }
  let response: Response
  try {
    response = await fetch(`/api/projects/${encodeURIComponent(projectId)}/graph?${query}`, {
      credentials: 'include', signal,
    })
  } catch (error) {
    if (signal?.aborted) throw error
    throw new ProjectApiError('Cannot reach the graph server.', { isNetworkError: true })
  }
  if (response.ok) return await response.json() as ExplorerGraph
  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to load graph relationships.', { status: response.status })
}

export class ProjectApiError extends ApiClientError {
  constructor(
    message: string,
    options?: ApiClientErrorOptions,
  ) {
    super(message, options)
    this.name = 'ProjectApiError'
  }
}

// In-memory mock store for mock mode
const mockProjects: Project[] = [
  {
    id: 'mock-proj-1',
    name: 'Payment Service',
    ecosystem: 'npm',
    description: 'Core payment processing backend and web services',
    created_at: Math.floor(Date.now() / 1000) - 3600,
  },
]

const mockJobs: IngestionJob[] = [
  {
    id: 'mock-job-1',
    project_id: 'mock-proj-1',
    job_type: 'dependency_import',
    status: 'succeeded',
    stage: 'Dependency import completed successfully',
    service_id: 'mock-proj-1:payment-api',
    service_name: 'payment-api',
    processed_items: 2,
    total_items: 2,
    percentage: 100,
    discovered_items: 2,
    created_items: 2,
    updated_items: 0,
    reused_items: 0,
    skipped_items: 0,
    failed_items: 0,
    error_summary: null,
    errors: [],
    warnings: [],
    retry_eligible: false,
    created_at: Math.floor(Date.now() / 1000) - 1800,
    started_at: Math.floor(Date.now() / 1000) - 1800,
    completed_at: Math.floor(Date.now() / 1000) - 1795,
    duration_ms: 5120,
    initiated_by: 'admin@vulnify.local',
    filename: 'package-lock.json',
    sha256_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    ecosystem: 'npm',
    import_method: 'npm_lockfile',
    fidelity: 'exact_lockfile',
  },
  {
    id: 'mock-job-2',
    project_id: 'mock-proj-1',
    job_type: 'osv_sync',
    status: 'succeeded',
    stage: 'Advisory ingestion complete',
    processed_items: 2,
    total_items: 2,
    percentage: 100,
    discovered_items: 1,
    created_items: 1,
    updated_items: 0,
    reused_items: 0,
    skipped_items: 0,
    failed_items: 0,
    errors: [],
    warnings: [],
    retry_eligible: false,
    created_at: Math.floor(Date.now() / 1000) - 1200,
    started_at: Math.floor(Date.now() / 1000) - 1200,
    completed_at: Math.floor(Date.now() / 1000) - 1198,
    duration_ms: 2450,
    initiated_by: 'admin@vulnify.local',
  },
]

export async function listProjects(): Promise<Project[]> {
  if (isMockMode()) {
    return [...mockProjects]
  }

  let response: Response
  try {
    response = await fetch('/api/projects', {
      method: 'GET',
      credentials: 'include',
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as Project[]
  }

  await handleErrorResponse(response)
  return []
}

export async function createProject(data: ProjectCreateRequest): Promise<Project> {
  if (isMockMode()) {
    const existing = mockProjects.find(
      (p) => p.name.trim().toLowerCase() === data.name.trim().toLowerCase(),
    )
    if (existing) {
      throw new ProjectApiError('A project with this name already exists.', {
        status: 409,
        code: 'CONFLICT',
      })
    }
    const newProj: Project = {
      id: `mock-proj-${Date.now()}`,
      name: data.name.trim(),
      ecosystem: data.ecosystem,
      description: data.description?.trim() || null,
      created_at: Math.floor(Date.now() / 1000),
    }
    mockProjects.unshift(newProj)
    return newProj
  }

  let response: Response
  try {
    response = await fetch('/api/projects', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'vulnify',
      },
      body: JSON.stringify(data),
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 201) {
    return (await response.json()) as Project
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to create project.', { status: response.status })
}

export async function getEcosystemCapabilities(): Promise<EcosystemCapabilitiesResponse> {
  if (isMockMode()) {
    return {
      supported_ecosystems: ['npm', 'PyPI', 'Cargo', 'Go'],
      capabilities: [
        {
          id: 'npm',
          display_name: 'npm (JavaScript / Node.js)',
          osv_ecosystem: 'npm',
          max_file_size_bytes: 10 * 1024 * 1024,
          max_packages: 5000,
          validation_rules: ['Valid UTF-8 JSON', 'package-lock.json v1, v2, or v3'],
          limitations: ['Does not execute lifecycle scripts'],
          supported_import_methods: [
            {
              id: 'npm_lockfile',
              name: 'npm package-lock.json',
              description: 'Resolved dependency tree from an npm package-lock.json file.',
              fidelity: 'exact_lockfile',
              fidelity_description: 'Extracts exact resolved versions and dependency edges.',
              accepted_filenames: ['package-lock.json', 'npm-shrinkwrap.json'],
              accepted_extensions: ['.json'],
              requires_paired_file: false,
              fields: [
                {
                  name: 'service_name',
                  label: 'Service Name',
                  type: 'string',
                  required: true,
                  description: 'Named microservice or application component.',
                },
                {
                  name: 'file',
                  label: 'Dependency File',
                  type: 'file',
                  required: true,
                  description: 'Primary lockfile.',
                },
              ],
              limitations: ['Requires package-lock.json v1-v3.'],
            },
          ],
        },
        {
          id: 'PyPI',
          display_name: 'PyPI (Python)',
          osv_ecosystem: 'PyPI',
          max_file_size_bytes: 10 * 1024 * 1024,
          max_packages: 5000,
          validation_rules: ['Valid TOML or requirements text'],
          limitations: ['setup.py without lockfile is not accepted'],
          supported_import_methods: [
            {
              id: 'poetry_lock',
              name: 'Poetry Lockfile (poetry.lock)',
              description: 'Fully resolved dependency tree from Poetry.',
              fidelity: 'exact_lockfile',
              fidelity_description: 'Extracts exact resolved package versions and edges.',
              accepted_filenames: ['poetry.lock'],
              accepted_extensions: ['.lock'],
              requires_paired_file: false,
              fields: [],
              limitations: [],
            },
            {
              id: 'uv_lock',
              name: 'uv Lockfile (uv.lock)',
              description: 'Modern Python dependency lockfile generated by Astral uv.',
              fidelity: 'exact_lockfile',
              fidelity_description: 'Extracts exact resolved package versions.',
              accepted_filenames: ['uv.lock'],
              accepted_extensions: ['.lock'],
              requires_paired_file: false,
              fields: [],
              limitations: [],
            },
            {
              id: 'pylock_toml',
              name: 'PEP 751 Lockfile (pylock.toml)',
              description: 'Standardized Python dependency lockfile conforming to PEP 751.',
              fidelity: 'exact_lockfile',
              fidelity_description: 'Extracts resolved package versions from standardized lockfile.',
              accepted_filenames: ['pylock.toml'],
              accepted_extensions: ['.toml'],
              requires_paired_file: false,
              fields: [],
              limitations: [],
            },
            {
              id: 'requirements_txt',
              name: 'Pinned Requirements (requirements.txt)',
              description: 'Declared direct dependencies from a Python requirements file.',
              fidelity: 'manifest_declared',
              fidelity_description: 'Only strictly pinned entries (package==version) provide verifiable exact versions.',
              accepted_filenames: ['requirements.txt'],
              accepted_extensions: ['.txt'],
              requires_paired_file: false,
              fields: [],
              limitations: ['Only pinned versions (package==X.Y.Z) are imported.'],
            },
          ],
        },
        {
          id: 'Cargo',
          display_name: 'Cargo (Rust)',
          osv_ecosystem: 'crates.io',
          max_file_size_bytes: 10 * 1024 * 1024,
          max_packages: 5000,
          validation_rules: ['Valid UTF-8 TOML Cargo.lock'],
          limitations: ['Cargo.toml without lockfile is not accepted'],
          supported_import_methods: [
            {
              id: 'cargo_lock',
              name: 'Cargo Lockfile (Cargo.lock)',
              description: 'Fully resolved dependency graph from Rust Cargo package manager.',
              fidelity: 'exact_lockfile',
              fidelity_description: 'Extracts exact crate versions, checksums, and dependency edges.',
              accepted_filenames: ['Cargo.lock'],
              accepted_extensions: ['.lock'],
              requires_paired_file: false,
              fields: [],
              limitations: [],
            },
          ],
        },
        {
          id: 'Go',
          display_name: 'Go (Golang)',
          osv_ecosystem: 'Go',
          max_file_size_bytes: 10 * 1024 * 1024,
          max_packages: 5000,
          validation_rules: ['Valid UTF-8 go.mod'],
          limitations: ['Inter-module edges are resolved via Go tooling'],
          supported_import_methods: [
            {
              id: 'go_mod',
              name: 'Go Module (go.mod with optional go.sum)',
              description: 'Go module dependencies from go.mod with optional paired checksum verification from go.sum.',
              fidelity: 'exact_lockfile',
              fidelity_description: 'Extracts module versions and verifies module checksums if go.sum is supplied.',
              accepted_filenames: ['go.mod'],
              accepted_extensions: ['.mod'],
              requires_paired_file: false,
              paired_file_name: 'go.sum',
              paired_file_description: 'Optional paired go.sum file for cryptographic module verification.',
              fields: [],
              limitations: [],
            },
          ],
        },
      ],
    }
  }

  let response: Response
  try {
    response = await fetch('/api/projects/ecosystem-capabilities', {
      method: 'GET',
      credentials: 'include',
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as EcosystemCapabilitiesResponse
  }

  await handleErrorResponse(response)
  return { supported_ecosystems: [], capabilities: [] }
}

export interface ImportDependenciesParams {
  serviceName: string
  file: File
  secondaryFile?: File | null
  importMethod?: string
}

export async function importDependencies(
  projectId: string,
  params: ImportDependenciesParams,
): Promise<ImportSummary> {
  const { serviceName, file, secondaryFile, importMethod } = params

  if (isMockMode()) {
    return {
      project_id: projectId,
      service_name: serviceName,
      filename: file.name,
      sha256_hash: 'mock_sha256_' + Array.from(file.name).reduce((acc, c) => acc + c.charCodeAt(0).toString(16), ''),
      packages_parsed: 12,
      packages_created: 12,
      packages_reused: 0,
      edges_created: 15,
      edges_reused: 0,
      skipped_entries: 0,
      warnings: [],
      errors: [],
      status: 'completed',
      imported_at: Math.floor(Date.now() / 1000),
      fidelity: 'exact_lockfile',
      ecosystem: 'npm',
      import_method: importMethod || 'lockfile',
      secondary_filename: secondaryFile ? secondaryFile.name : null,
    }
  }

  const formData = new FormData()
  formData.append('service_name', serviceName)
  formData.append('file', file)
  if (secondaryFile) {
    formData.append('secondary_file', secondaryFile)
  }
  if (importMethod) {
    formData.append('import_method', importMethod)
  }

  let response: Response
  try {
    response = await fetch(`/api/projects/${encodeURIComponent(projectId)}/dependencies/import`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
      body: formData,
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as ImportSummary
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to import dependencies.', { status: response.status })
}

export async function importLockfile(
  projectId: string,
  serviceName: string,
  file: File,
): Promise<ImportSummary> {
  return importDependencies(projectId, { serviceName, file })
}

const mockAdvisoriesStore: Record<string, ProjectAdvisory[]> = {
  'mock-proj-1': [
    {
      id: 'GHSA-example-lodash-proto',
      summary: 'Prototype pollution in lodash',
      details: 'Vulnerable versions of lodash are susceptible to prototype pollution.',
      severity: 'CRITICAL',
      cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      aliases: ['CVE-2019-10744'],
      published: '2019-07-02T00:00:00Z',
      modified: '2023-01-15T00:00:00Z',
      source_url: 'https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw',
      retrieved_at: Math.floor(Date.now() / 1000) - 1200,
      package_version_id: 'npm:lodash@4.17.15',
      package_name: 'lodash',
      package_version: '4.17.15',
      ecosystem: 'npm',
    },
  ],
}

export async function importAdvisories(
  projectId: string,
  forceRefresh: boolean = false,
): Promise<OsvImportSummary> {
  if (isMockMode()) {
    const existing = mockAdvisoriesStore[projectId] || []
    return {
      project_id: projectId,
      total_package_versions: 12,
      eligible_package_versions: 12,
      unique_lookups: 8,
      cache_hits: forceRefresh ? 0 : 3,
      advisories_found: existing.length,
      advisories_created: existing.length,
      advisories_updated: 0,
      relationships_created: existing.length,
      relationships_reused: 0,
      packages_with_advisories: existing.length,
      packages_with_no_advisories: 7,
      skipped_packages: 0,
      failed_lookups: 0,
      status: 'completed',
      errors: [],
      duration_ms: 185.4,
      package_results: [],
    }
  }

  const queryParam = forceRefresh ? '?force_refresh=true' : ''
  let response: Response
  try {
    response = await fetch(`/api/projects/${encodeURIComponent(projectId)}/advisories/import${queryParam}`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as OsvImportSummary
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to import advisories.', { status: response.status })
}

export async function getProjectAdvisories(projectId: string): Promise<ProjectAdvisory[]> {
  if (isMockMode()) {
    return [...(mockAdvisoriesStore[projectId] || [])]
  }

  let response: Response
  try {
    response = await fetch(`/api/projects/${encodeURIComponent(projectId)}/advisories`, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as ProjectAdvisory[]
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch project advisories.', { status: response.status })
}

const mockPackageVersions: Record<string, PackageVersion[]> = {
  'mock-proj-1': [
    {
      id: 'npm:lodash@4.17.20',
      name: 'lodash',
      version: '4.17.20',
      ecosystem: 'npm',
      purl: 'pkg:npm/lodash@4.17.20',
    },
    {
      id: 'npm:express@4.18.2',
      name: 'express',
      version: '4.18.2',
      ecosystem: 'npm',
      purl: 'pkg:npm/express@4.18.2',
    },
    {
      id: 'npm:accepts@1.3.8',
      name: 'accepts',
      version: '1.3.8',
      ecosystem: 'npm',
      purl: 'pkg:npm/accepts@1.3.8',
    },
  ],
}

export async function getProjectPackages(projectId: string): Promise<PackageVersion[]> {
  if (isMockMode()) {
    return [...(mockPackageVersions[projectId] || [])]
  }

  let response: Response
  try {
    response = await fetch(`/api/projects/${encodeURIComponent(projectId)}/packages`, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as PackageVersion[]
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch project package versions.', { status: response.status })
}

export async function matchProjectVulnerabilities(projectId: string): Promise<ProjectMatchResponse> {
  if (isMockMode()) {
    return {
      project_id: projectId,
      total_evaluated: 1,
      affected_count: 1,
      not_affected_count: 0,
      unknown_count: 0,
      relationships_persisted: 1,
      relationships_removed: 0,
      duration_ms: 25.4,
      status: 'completed',
      results: [
        {
          package_name: 'lodash',
          package_version: '4.17.20',
          ecosystem: 'npm',
          advisory_id: 'GHSA-29mw-wpgm-hmr9',
          status: 'affected',
          reason_code: 'WITHIN_AFFECTED_RANGE',
          reason: 'Version 4.17.20 is within affected range (< 4.17.21) for advisory GHSA-29mw-wpgm-hmr9.',
          matched_range: '< 4.17.21',
          fixed_version: '4.17.21',
          comparator: 'semver',
          evaluated_at: Math.floor(Date.now() / 1000),
          fingerprint: 'mock-fingerprint-lodash-41720',
        },
      ],
    }
  }

  let response: Response
  try {
    response = await fetch(`/api/projects/${encodeURIComponent(projectId)}/vulnerabilities/match`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as ProjectMatchResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to execute version matching.', { status: response.status })
}

export async function getProjectVulnerabilities(projectId: string): Promise<VulnerabilityFinding[]> {
  if (isMockMode()) {
    return [
      {
        id: 'GHSA-29mw-wpgm-hmr9',
        summary: 'Regular Expression Denial of Service (ReDoS) in lodash',
        severity: 'HIGH',
        aliases: ['CVE-2020-28500'],
        package_version_id: 'mock-pv-1',
        package_name: 'lodash',
        package_version: '4.17.20',
        ecosystem: 'npm',
        match_status: 'affected',
        match_reason: 'Version 4.17.20 is within affected range (< 4.17.21) for advisory GHSA-29mw-wpgm-hmr9.',
        reason_code: 'WITHIN_AFFECTED_RANGE',
        matched_range: '< 4.17.21',
        fixed_version: '4.17.21',
        evaluated_at: Math.floor(Date.now() / 1000),
        comparator: 'semver',
        fingerprint: 'mock-fingerprint-lodash-41720',
      },
    ]
  }

  let response: Response
  try {
    response = await fetch(`/api/projects/${encodeURIComponent(projectId)}/vulnerabilities`, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as VulnerabilityFinding[]
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch vulnerability findings.', { status: response.status })
}

export async function listIngestionJobs(
  projectId: string,
  params?: ListJobsFilterParams,
): Promise<IngestionJobListResponse> {
  if (isMockMode()) {
    let filtered = mockJobs.filter((j) => j.project_id === projectId)
    if (params?.status) {
      filtered = filtered.filter((j) => j.status === params.status)
    }
    if (params?.job_type) {
      filtered = filtered.filter((j) => j.job_type === params.job_type)
    }
    if (params?.service_name) {
      const q = params.service_name.toLowerCase().trim()
      filtered = filtered.filter((j) => j.service_name?.toLowerCase().includes(q))
    }
    const page = params?.page ?? 1
    const pageSize = params?.page_size ?? 20
    const total = filtered.length
    const totalPages = Math.ceil(total / pageSize) || 1
    const paginated = filtered.slice((page - 1) * pageSize, page * pageSize)

    const allProjectJobs = mockJobs.filter((j) => j.project_id === projectId)
    return {
      items: paginated,
      total,
      page,
      page_size: pageSize,
      total_pages: totalPages,
      summary_stats: {
        total_runs: allProjectJobs.length,
        running_runs: allProjectJobs.filter((j) => j.status === 'running' || j.status === 'queued').length,
        succeeded_runs: allProjectJobs.filter((j) => j.status === 'succeeded').length,
        failed_runs: allProjectJobs.filter((j) => j.status === 'failed').length,
        partial_runs: allProjectJobs.filter((j) => j.status === 'partial').length,
      },
    }
  }

  const searchParams = new URLSearchParams()
  if (params?.page) searchParams.set('page', String(params.page))
  if (params?.page_size) searchParams.set('page_size', String(params.page_size))
  if (params?.status) searchParams.set('status', params.status)
  if (params?.job_type) searchParams.set('job_type', params.job_type)
  if (params?.service_name) searchParams.set('service_name', params.service_name)

  const query = searchParams.toString() ? `?${searchParams.toString()}` : ''
  let response: Response
  try {
    response = await fetch(`/api/projects/${encodeURIComponent(projectId)}/jobs${query}`, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as IngestionJobListResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to list ingestion jobs.', { status: response.status })
}

export async function getIngestionJob(
  projectId: string,
  jobId: string,
): Promise<IngestionJob> {
  if (isMockMode()) {
    const job = mockJobs.find((j) => j.project_id === projectId && j.id === jobId)
    if (!job) {
      throw new ProjectApiError('Ingestion job not found.', { status: 404, code: 'NOT_FOUND' })
    }
    return { ...job }
  }

  let response: Response
  try {
    response = await fetch(`/api/projects/${encodeURIComponent(projectId)}/jobs/${encodeURIComponent(jobId)}`, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as IngestionJob
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch ingestion job.', { status: response.status })
}

export async function retryIngestionJob(
  projectId: string,
  jobId: string,
): Promise<JobRetryResponse> {
  if (isMockMode()) {
    const orig = mockJobs.find((j) => j.project_id === projectId && j.id === jobId)
    if (!orig) {
      throw new ProjectApiError('Ingestion job not found.', { status: 404, code: 'NOT_FOUND' })
    }
    if (orig.status !== 'failed' && orig.status !== 'partial') {
      throw new ProjectApiError('Only failed or partial jobs are eligible for retry.', { status: 400, code: 'BAD_REQUEST' })
    }
    const newJob: IngestionJob = {
      ...orig,
      id: `mock-job-${Date.now()}`,
      status: 'succeeded',
      stage: 'Completed after retry',
      retry_of_job_id: orig.id,
      created_at: Math.floor(Date.now() / 1000),
      started_at: Math.floor(Date.now() / 1000),
      completed_at: Math.floor(Date.now() / 1000) + 2,
    }
    mockJobs.unshift(newJob)
    return {
      message: `Job ${jobId} successfully retried.`,
      original_job_id: orig.id,
      new_job: newJob,
    }
  }

  let response: Response
  try {
    response = await fetch(`/api/projects/${encodeURIComponent(projectId)}/jobs/${encodeURIComponent(jobId)}/retry`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as JobRetryResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to retry ingestion job.', { status: response.status })
}

export async function listProjectServices(projectId: string): Promise<ProjectService[]> {
  if (isMockMode()) {
    return [
      { id: `${projectId}:payment-api`, name: 'payment-api' },
      { id: `${projectId}:auth-api`, name: 'auth-api' },
    ]
  }

  let response: Response
  try {
    response = await fetch(`/api/projects/${encodeURIComponent(projectId)}/services`, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as ProjectService[]
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch project services.', { status: response.status })
}

const mockFindingsStore: Record<string, FindingItem[]> = {
  'mock-proj-1': [
    {
      id: 'mock-finding-1',
      project_id: 'mock-proj-1',
      service_id: 'mock-proj-1:payment-api',
      service_name: 'payment-api',
      advisory_id: 'GHSA-29mw-wpgm-hmr9',
      advisory_summary: 'Regular Expression Denial of Service (ReDoS) in lodash',
      source_url: 'https://github.com/advisories/GHSA-29mw-wpgm-hmr9',
      package_name: 'lodash',
      ecosystem: 'npm',
      package_version: '4.17.20',
      package_version_id: 'npm:lodash@4.17.20',
      priority: 'High',
      priority_reasons: [
        'Advisory severity is High',
        'Transitive dependency reachable from service (path depth: 2 hops)',
        'Actionable remediation target available (fixed in >= 4.17.21)',
      ],
      scoring_version: 'v1.0.0',
      status: 'open',
      path_depth: 2,
      path_status: 'path_found',
      match_reason: 'Version 4.17.20 is within affected range (< 4.17.21) for advisory GHSA-29mw-wpgm-hmr9.',
      reason_code: 'WITHIN_AFFECTED_RANGE',
      matched_range: '< 4.17.21',
      fixed_version: '4.17.21',
      severity: 'HIGH',
      retrieved_at: Math.floor(Date.now() / 1000) - 3600,
    },
  ],
  'mock-proj-2': [
    {
      id: 'mock-finding-proj2-1',
      project_id: 'mock-proj-2',
      service_id: 'mock-proj-2:auth-api',
      service_name: 'auth-api',
      advisory_id: 'GHSA-3647-7977-m75v',
      advisory_summary: 'Prototype Pollution in json-pointer',
      source_url: 'https://github.com/advisories/GHSA-3647-7977-m75v',
      package_name: 'json-pointer',
      ecosystem: 'npm',
      package_version: '0.6.1',
      package_version_id: 'npm:json-pointer@0.6.1',
      priority: 'Highest',
      priority_reasons: [
        'Advisory severity is Critical',
        'Direct dependency reachable from internet-facing service',
      ],
      scoring_version: 'v1.0.0',
      status: 'open',
      path_depth: 1,
      path_status: 'path_found',
      match_reason: 'Version 0.6.1 is affected',
      reason_code: 'WITHIN_AFFECTED_RANGE',
      severity: 'CRITICAL',
      retrieved_at: Math.floor(Date.now() / 1000) - 3600,
    },
  ],
}

function getMockFindings(projectId: string): FindingItem[] {
  return mockFindingsStore[projectId] || []
}

export async function getProjectFindings(
  projectId: string,
  params?: FindingFilters,
): Promise<FindingListResponse> {
  if (isMockMode()) {
    const mockFindings = getMockFindings(projectId)
    let filtered = [...mockFindings]
    if (params?.service_id) {
      filtered = filtered.filter((f) => f.service_id === params.service_id)
    }
    if (params?.search) {
      const q = params.search.toLowerCase()
      filtered = filtered.filter(
        (f) => f.advisory_id.toLowerCase().includes(q) || f.package_name.toLowerCase().includes(q),
      )
    }
    if (params?.priority) {
      filtered = filtered.filter((f) => f.priority.toLowerCase() === params.priority?.toLowerCase())
    }
    if (params?.status) {
      filtered = filtered.filter((f) => f.status.toLowerCase() === params.status?.toLowerCase())
    }

    const pageSize = params?.page_size ?? 25
    const page = params?.page ?? 1
    const total = filtered.length
    const totalPages = Math.ceil(total / pageSize)
    const offset = (page - 1) * pageSize
    const items = filtered.slice(offset, offset + pageSize)

    return {
      items,
      page,
      page_size: pageSize,
      total,
      total_pages: totalPages,
    }
  }

  const queryParams = new URLSearchParams()
  if (params?.page) queryParams.set('page', String(params.page))
  if (params?.page_size) queryParams.set('page_size', String(params.page_size))
  if (params?.priority) queryParams.set('priority', params.priority)
  if (params?.service_id) queryParams.set('service_id', params.service_id)
  if (params?.status) queryParams.set('status', params.status)
  if (params?.search) queryParams.set('search', params.search)
  if (params?.sort_by) queryParams.set('sort_by', params.sort_by)

  const queryString = queryParams.toString()
  const url = `/api/projects/${encodeURIComponent(projectId)}/findings${queryString ? `?${queryString}` : ''}`

  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as FindingListResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch project findings.', { status: response.status })
}

export async function getProjectFindingsSummary(
  projectId: string,
  params?: FindingFilters,
): Promise<FindingSummaryResponse> {
  if (isMockMode()) {
    const listResponse = await getProjectFindings(projectId, params)
    const items = listResponse.items
    const withPath = items.filter(
      (f) => f.path_status === 'path_found' || (f.path_depth !== null && f.path_depth >= 1),
    ).length
    const withoutPath = items.length - withPath
    const needingDecision = items.filter((f) =>
      ['open', 'under_investigation'].includes(f.status.toLowerCase()),
    ).length
    return {
      project_id: projectId,
      advisory_matches: listResponse.total,
      findings_with_path: withPath,
      findings_without_path: withoutPath,
      findings_needing_decision: needingDecision,
    }
  }

  const queryParams = new URLSearchParams()
  if (params?.priority) queryParams.set('priority', params.priority)
  if (params?.service_id) queryParams.set('service_id', params.service_id)
  if (params?.status) queryParams.set('status', params.status)
  if (params?.search) queryParams.set('search', params.search)

  const queryString = queryParams.toString()
  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/summary${queryString ? `?${queryString}` : ''}`

  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as FindingSummaryResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch project findings summary.', { status: response.status })
}

export async function getProjectFindingDetail(
  projectId: string,
  findingId: string,
): Promise<FindingDetail> {
  if (isMockMode()) {
    const list = await getProjectFindings(projectId, { page: 1, page_size: 100 })
    const item = list.items.find(
      (f) =>
        f.id.toLowerCase() === findingId.toLowerCase() ||
        f.advisory_id.toLowerCase() === findingId.toLowerCase(),
    )
    if (!item) {
      throw new ProjectApiError(`Finding '${findingId}' not found in project '${projectId}'.`, {
        status: 404,
        code: 'NOT_FOUND',
      })
    }
    return {
      ...item,
      advisory_details:
        item.advisory_summary ||
        `Detailed description for advisory ${item.advisory_id} affecting package ${item.package_name}.`,
      aliases: [],
    }
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as FindingDetail
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch finding detail.', { status: response.status })
}

export async function getFindingDependencyPaths(
  projectId: string,
  findingId: string,
  params?: { max_depth?: number; limit?: number },
): Promise<FindingPathsResponse> {
  if (isMockMode()) {
    const detail = await getProjectFindingDetail(projectId, findingId)
    const isDirect = (detail.path_depth ?? 1) === 1
    const serviceNodeId = detail.service_id
    const targetNodeId = detail.package_version_id

    const nodes: PathNode[] = [
      {
        id: serviceNodeId,
        node_type: 'service',
        display_name: detail.service_name,
        is_target: false,
        is_entry_point: true,
        provenance: {
          source_filename: 'package-lock.json',
          content_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          imported_at: Math.floor(Date.now() / 1000) - 3600,
          classification: 'manifest',
          origin: 'stored_graph',
        },
      },
    ]

    const edges: PathEdge[] = []

    if (!isDirect) {
      const intermediateId = `${detail.ecosystem}:intermediate-lib@1.0.0`
      nodes.push({
        id: intermediateId,
        node_type: 'package' as const,
        display_name: 'intermediate-lib@1.0.0',
        package_name: 'intermediate-lib',
        package_version: '1.0.0',
        ecosystem: detail.ecosystem,
        purl: `pkg:${detail.ecosystem}/intermediate-lib@1.0.0`,
        is_target: false,
        is_entry_point: false,
        provenance: {
          source_filename: 'package-lock.json',
          content_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          imported_at: Math.floor(Date.now() / 1000) - 3600,
          classification: 'manifest',
          origin: 'stored_graph',
        },
      })
      edges.push({
        id: `edge-${serviceNodeId}->${intermediateId}`,
        source_id: serviceNodeId,
        target_id: intermediateId,
        relationship_type: 'DEPENDS_ON',
        direct: true,
        origin: 'manifest',
      })
    }

    const lastSrcId = nodes[nodes.length - 1].id
    nodes.push({
      id: targetNodeId,
      node_type: 'package' as const,
      display_name: `${detail.package_name}@${detail.package_version}`,
      package_name: detail.package_name,
      package_version: detail.package_version,
      ecosystem: detail.ecosystem,
      purl: detail.package_version_id,
      is_target: true,
      is_entry_point: false,
      provenance: {
        source_filename: 'package-lock.json',
        content_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        imported_at: Math.floor(Date.now() / 1000) - 3600,
        classification: 'manifest',
        origin: 'stored_graph',
      },
    })
    edges.push({
      id: `edge-${lastSrcId}->${targetNodeId}`,
      source_id: lastSrcId,
      target_id: targetNodeId,
      relationship_type: 'DEPENDS_ON',
      direct: isDirect,
      origin: 'manifest',
    })

    const summaryParts = [nodes[0].display_name, ...nodes.slice(1).map((n) => n.display_name)]
    const summaryText = `Service: ${summaryParts.join(' → ')}`

    return {
      project_id: projectId,
      finding_id: detail.id,
      service_id: detail.service_id,
      service_name: detail.service_name,
      advisory_id: detail.advisory_id,
      package_name: detail.package_name,
      package_version: detail.package_version,
      package_version_id: detail.package_version_id,
      paths: [
        {
          id: `path-${detail.id}-0`,
          depth: isDirect ? 1 : 2,
          is_direct: isDirect,
          nodes,
          edges,
          summary_text: summaryText,
        },
      ],
      total_paths_found: 1,
      max_depth_applied: params?.max_depth ?? 8,
      limit_applied: params?.limit ?? 5,
      is_truncated: false,
      has_path: true,
      evaluated_at: Math.floor(Date.now() / 1000),
    }
  }

  const queryParams = new URLSearchParams()
  if (params?.max_depth !== undefined) queryParams.set('max_depth', String(params.max_depth))
  if (params?.limit !== undefined) queryParams.set('limit', String(params.limit))
  const queryString = queryParams.toString()

  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/paths${queryString ? `?${queryString}` : ''}`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as FindingPathsResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch finding dependency paths.', { status: response.status })
}

export async function getProjectExposurePaths(
  projectId: string,
  params?: { findingId?: string; serviceId?: string; limit?: number },
): Promise<ProjectExposurePathsResponse> {
  if (isMockMode()) {
    return {
      project_id: projectId,
      topology_status: 'complete',
      has_internet_exposure: true,
      total_exposure_paths: 0,
      items: [],
      unsupported_ecosystems: [],
      disclaimer:
        'Architectural exposure, not proof of exploitability. Paths show architectural reachability through service and dependency topology, not runtime exploit execution. Absence of a path does not guarantee safety.',
      warnings: [],
      evaluated_at: Math.floor(Date.now() / 1000),
    }
  }

  const queryParams = new URLSearchParams()
  if (params?.findingId) queryParams.set('finding_id', params.findingId)
  if (params?.serviceId) queryParams.set('service_id', params.serviceId)
  if (params?.limit !== undefined) queryParams.set('limit', String(params.limit))
  const queryString = queryParams.toString()

  const url = `/api/projects/${encodeURIComponent(projectId)}/exposure-paths${queryString ? `?${queryString}` : ''}`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as ProjectExposurePathsResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch architectural exposure paths.', { status: response.status })
}

export async function getFindingExposurePaths(
  projectId: string,
  findingId: string,
  params?: { limit?: number },
): Promise<ProjectExposurePathsResponse> {
  if (isMockMode()) {
    return {
      project_id: projectId,
      topology_status: 'complete',
      has_internet_exposure: true,
      total_exposure_paths: 0,
      items: [],
      unsupported_ecosystems: [],
      disclaimer:
        'Architectural exposure, not proof of exploitability. Paths show architectural reachability through service and dependency topology, not runtime exploit execution. Absence of a path does not guarantee safety.',
      warnings: [],
      evaluated_at: Math.floor(Date.now() / 1000),
    }
  }

  const queryParams = new URLSearchParams()
  if (params?.limit !== undefined) queryParams.set('limit', String(params.limit))
  const queryString = queryParams.toString()

  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/exposure-paths${queryString ? `?${queryString}` : ''}`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as ProjectExposurePathsResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch finding exposure paths.', { status: response.status })
}

export async function getProjectDataQuality(
  projectId: string,
): Promise<ProjectDataQualityResponse> {
  if (isMockMode()) {
    return {
      project_id: projectId,
      has_warnings: false,
      warning_count: 0,
      warnings: [],
      evaluated_at: Math.floor(Date.now() / 1000),
    }
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/data-quality`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as ProjectDataQualityResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch project data quality warnings.', { status: response.status })
}

export async function getFindingUpgradeCandidates(
  projectId: string,
  findingId: string,
): Promise<UpgradeCandidatesResponse> {
  if (isMockMode()) {
    return {
      project_id: projectId,
      finding_id: findingId,
      advisory_id: 'GHSA-mock-fix',
      package_name: 'mock-lib',
      current_version: '1.0.0',
      ecosystem: 'npm',
      service_id: `${projectId}:api`,
      service_name: 'api',
      path_depth: 1,
      is_transitive: false,
      has_fix: true,
      candidates: [
        {
          target_version: '1.0.1',
          classification: 'recommended',
          label: 'Recommended',
          labels: ['recommended', 'patch only'],
          semver_diff: 'patch',
          is_recommended: true,
          fix_status: 'fix_supported',
          compatibility_status: 'compatible',
          breaking_change_risk: 'low',
          caveats: [
            'Patch-only upgrade (v1.0.0 -> v1.0.1): Backwards-compatible bug and security fix.',
            'Direct dependency: Check declared manifest constraints in lockfile/manifest.',
            'Absence of detected conflicts does not guarantee runtime compatibility or application safety. Vulnify never claims an upgrade is safe to ship without project-level integration and regression testing.',
          ],
          evidence_source: 'Advisory fixed version declaration',
        },
      ],
      no_fix_message: null,
      remediation_guidance: 'Review candidate SemVer diffs, check for breaking API changes, and test before applying.',
      safety_disclaimer:
        'No upgrade is guaranteed safe to ship. Upstream fixed versions indicate that the security advisory reports the vulnerability as resolved in that release. Upgrades may introduce regressions, breaking changes, or undeclared side effects. Always run test suites and security validation before deploying to production.',
      evaluated_at: Math.floor(Date.now() / 1000),
    }
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/upgrade-candidates`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as UpgradeCandidatesResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch upgrade candidates.', { status: response.status })
}

export async function getProjectUpgradeCandidates(
  projectId: string,
): Promise<ProjectUpgradeCandidatesResponse> {
  if (isMockMode()) {
    return {
      project_id: projectId,
      total_findings: 1,
      findings_with_fix: 1,
      findings_without_fix: 0,
      items: [],
      safety_disclaimer:
        'No upgrade is guaranteed safe to ship. Upstream fixed versions indicate that the security advisory reports the vulnerability as resolved in that release. Upgrades may introduce regressions, breaking changes, or undeclared side effects. Always run test suites and security validation before deploying to production.',
      evaluated_at: Math.floor(Date.now() / 1000),
    }
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/upgrade-candidates`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as ProjectUpgradeCandidatesResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch project upgrade candidates.', { status: response.status })
}

// =====================================================================
// US-501 / US-502: Fix Simulation API Methods
// =====================================================================

const mockSimulationsStore: Record<string, SimulationResponse[]> = {}

export async function simulateFix(
  projectId: string,
  request: SimulationRequest,
): Promise<SimulationResponse> {
  if (isMockMode()) {
    const sim: SimulationResponse = {
      id: `sim-mock-${Date.now()}`,
      project_id: projectId,
      package_name: request.package_name,
      current_version: request.current_version,
      target_version: request.target_version,
      ecosystem: request.ecosystem || 'npm',
      service_id: request.service_id || null,
      service_name: 'payment-api',
      method: 'simulated_from_metadata',
      method_description:
        'Evaluated on an in-memory graph overlay using OSV advisory version metadata and lockfile dependency paths without mutating stored graph data.',
      is_simulation: true,
      real_graph_mutated: false,
      baseline_id: `snap-${Date.now().toString(16)}`,
      is_transitive: false,
      path_depth: 1,
      paths_severed_count: 1,
      paths_remaining_count: 0,
      dependent_services: ['payment-api'],
      cleared_findings: [
        {
          finding_id: request.finding_id || 'find-mock-1',
          advisory_id: 'GHSA-mock-sample',
          package_name: request.package_name,
          installed_version: request.current_version,
          target_version: request.target_version,
          severity: 'HIGH',
          status: 'expected_resolved',
          explanation: `Proposed target version ${request.target_version} satisfies upstream fixed version requirements.`,
          source_url: 'https://osv.dev',
        },
      ],
      unchanged_findings: [],
      newly_introduced_findings: [],
      total_findings_cleared: 1,
      total_findings_unchanged: 0,
      total_findings_introduced: 0,
      compatibility_status: 'compatible',
      breaking_change_risk: 'low',
      resolver_status: 'not_evaluated',
      compatibility_caveats: [
        'Absence of detected conflicts does not guarantee runtime compatibility or application safety.',
        'Graph simulation only: real package manager resolution and container runtime were not executed.',
      ],
      checks_performed: [
        {
          name: 'Advisory Fixed Version Verification',
          status: 'passed',
          description: `Evaluated baseline findings for ${request.package_name} against target version ${request.target_version}. 1 expected to clear.`,
        },
        {
          name: 'Graph Path Exposure Analysis',
          status: 'passed',
          description: 'Simulated severing of 1 vulnerable reachability path(s) on graph overlay.',
        },
        {
          name: 'SemVer Compatibility & Breaking Risk',
          status: 'passed',
          description: "SemVer differential assessed as 'patch' jump with 'low' breaking change risk.",
        },
        {
          name: 'Package Manager Lockfile Resolution',
          status: 'not_evaluated',
          description: 'Graph simulation only; real package-manager resolution (npm/pip) was not executed.',
        },
        {
          name: 'Runtime Sandbox Execution',
          status: 'not_evaluated',
          description: 'Non-mutating metadata simulation; dynamic container execution not performed.',
        },
      ],
      safety_disclaimer:
        'No upgrade is guaranteed safe to ship. Upstream fixed versions indicate that the security advisory reports the vulnerability as resolved in that release. Upgrades may introduce regressions, breaking changes, or undeclared side effects. Always run test suites and security validation before deploying to production.',
      created_at: Math.floor(Date.now() / 1000),
    }

    if (!mockSimulationsStore[projectId]) {
      mockSimulationsStore[projectId] = []
    }
    mockSimulationsStore[projectId].unshift(sim)
    return sim
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/simulations`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'vulnify',
      },
      body: JSON.stringify(request),
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as SimulationResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to run fix simulation.', { status: response.status })
}

export async function getProjectSimulations(
  projectId: string,
): Promise<SimulationListResponse> {
  if (isMockMode()) {
    const list = mockSimulationsStore[projectId] || []
    return {
      items: list,
      total: list.length,
    }
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/simulations`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as SimulationListResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch project simulations.', { status: response.status })
}

export async function getSimulationDetail(
  projectId: string,
  simulationId: string,
): Promise<SimulationResponse> {
  if (isMockMode()) {
    const list = mockSimulationsStore[projectId] || []
    const found = list.find((s) => s.id === simulationId)
    if (found) return found
    throw new ProjectApiError('Simulation not found.', { status: 404 })
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/simulations/${encodeURIComponent(simulationId)}`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as SimulationResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch simulation detail.', { status: response.status })
}

// =====================================================================
// US-503 / US-504: GitHub Remediation Issues API
// =====================================================================

const mockGitHubIssuesStore: Record<string, GitHubIssueRecordResponse[]> = {}

export async function getGitHubStatus(
  projectId: string,
): Promise<GitHubIntegrationStatusResponse> {
  if (isMockMode()) {
    return {
      configured: true,
      default_owner: 'vulnify',
      default_repo: 'demo-workspace',
      target_repo: 'vulnify/demo-workspace',
      api_base_url: 'https://api.github.com',
    }
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/github/status`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as GitHubIntegrationStatusResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch GitHub integration status.', { status: response.status })
}

export async function getGitHubConfig(projectId?: string): Promise<GitHubConfigResponse> {
  if (isMockMode()) {
    return {
      configured: true,
      owner: 'vulnify',
      repo: 'demo-workspace',
      target_repo: 'vulnify/demo-workspace',
      has_token: true,
      api_base_url: 'https://api.github.com',
      validation_status: 'valid',
      validation_message: 'Mock integration active and healthy',
      last_validated_at: Math.floor(Date.now() / 1000) - 300,
      updated_at: Math.floor(Date.now() / 1000) - 3600,
      updated_by: 'admin@vulnify.local',
      project_id: projectId || null,
    }
  }

  const url = projectId
    ? `/api/projects/${encodeURIComponent(projectId)}/github/config`
    : '/api/admin/github-config'

  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as GitHubConfigResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch GitHub configuration.', { status: response.status })
}

export async function updateGitHubConfig(
  data: GitHubConfigUpdateRequest,
): Promise<GitHubConfigResponse> {
  if (isMockMode()) {
    return {
      configured: true,
      owner: data.owner,
      repo: data.repo,
      target_repo: `${data.owner}/${data.repo}`,
      has_token: Boolean(data.token) || true,
      api_base_url: data.api_base_url || 'https://api.github.com',
      validation_status: 'valid',
      validation_message: `Repository '${data.owner}/${data.repo}' verified and saved in mock mode.`,
      last_validated_at: Math.floor(Date.now() / 1000),
      updated_at: Math.floor(Date.now() / 1000),
      updated_by: 'admin@vulnify.local',
      project_id: data.project_id || null,
    }
  }

  const url = data.project_id
    ? `/api/projects/${encodeURIComponent(data.project_id)}/github/config`
    : '/api/admin/github-config'
  const method = data.project_id ? 'PUT' : 'POST'

  let response: Response
  try {
    response = await fetch(url, {
      method,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'vulnify',
      },
      body: JSON.stringify(data),
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as GitHubConfigResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to update GitHub configuration.', { status: response.status })
}

export async function validateGitHubConfig(
  data: GitHubConfigValidateRequest,
): Promise<GitHubValidationResult> {
  if (isMockMode()) {
    return {
      valid: true,
      status: 'valid',
      message: `Successfully connected to repository '${data.owner}/${data.repo}'. Token has permissions to create remediation issues (Mock Mode).`,
      owner: data.owner,
      repo: data.repo,
      target_repo: `${data.owner}/${data.repo}`,
      has_issues_enabled: true,
      has_write_access: true,
      checked_at: Math.floor(Date.now() / 1000),
    }
  }

  const url = data.project_id
    ? `/api/projects/${encodeURIComponent(data.project_id)}/github/validate`
    : '/api/admin/github-config/validate'

  let response: Response
  try {
    response = await fetch(url, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'vulnify',
      },
      body: JSON.stringify(data),
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as GitHubValidationResult
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to validate GitHub configuration.', { status: response.status })
}

export async function previewGitHubIssue(
  projectId: string,
  findingId: string,
  request: GitHubIssuePreviewRequest = {},
): Promise<GitHubIssuePreviewResponse> {
  if (isMockMode()) {
    const mockFindings = getMockFindings(projectId)
    const finding = mockFindings.find((f: FindingItem) => f.id === findingId)
    const pkg = finding?.package_name || 'lodash'
    const cur = finding?.package_version || '4.17.20'
    const target = request.target_version || finding?.fixed_version || '4.17.21'
    const title =
      request.title_override ||
      `[Security] Remediate ${pkg}@${cur} (${finding?.advisory_id || findingId})`
    const body =
      request.body_override ||
      `## Vulnerability Remediation Request\n\n` +
      `### Target Package\n` +
      `- **Package:** \`${pkg}\`\n` +
      `- **Installed Version:** \`${cur}\`\n` +
      `- **Target Fix Version:** \`${target}\`\n` +
      `- **Advisory Reference:** ${finding?.advisory_id || findingId}\n\n` +
      `### Reachability Evidence\n` +
      `- **Exposure:** Confirmed reachability path in service dependency graph.\n\n` +
      `*Architectural exposure indicates structural reachability; it does not constitute proof of active runtime exploitability.*`

    const planHash = `plan_sha256_${Math.random().toString(16).slice(2, 10)}${Math.random().toString(16).slice(2, 10)}`
    return {
      project_id: projectId,
      finding_id: findingId,
      advisory_id: finding?.advisory_id || 'GHSA-mock',
      package_name: pkg,
      current_version: cur,
      target_version: target,
      ecosystem: finding?.ecosystem || 'npm',
      service_name: finding?.service_name || 'order-api',
      target_repo: request.target_repo || 'vulnify/demo-workspace',
      title,
      body,
      plan_hash: planHash,
      can_submit: true,
      configuration_warning: null,
      generated_at: Math.floor(Date.now() / 1000),
    }
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/github-issues/preview`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'vulnify',
      },
      body: JSON.stringify(request),
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as GitHubIssuePreviewResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to generate issue preview.', { status: response.status })
}

export async function createGitHubIssue(
  projectId: string,
  findingId: string,
  request: GitHubIssueCreateRequest,
): Promise<GitHubIssueRecordResponse> {
  if (isMockMode()) {
    if (!request.confirmed) {
      throw new ProjectApiError("Issue creation requires explicit human approval ('confirmed': true).", {
        status: 400,
      })
    }
    const store = mockGitHubIssuesStore[projectId] || []
    const existing = store.find((i) => i.plan_hash === request.plan_hash)
    if (existing) {
      return {
        ...existing,
        is_duplicate: true,
        message: `Duplicate creation prevented. Plan hash ${request.plan_hash.slice(0, 16)} already filed.`,
      }
    }
    const issueNumber = 100 + store.length + 1
    const record: GitHubIssueRecordResponse = {
      id: `gh-issue-${Date.now()}`,
      project_id: projectId,
      finding_id: findingId,
      target_repo: request.target_repo,
      issue_number: issueNumber,
      issue_url: `https://github.com/${request.target_repo}/issues/${issueNumber}`,
      title: request.title,
      plan_hash: request.plan_hash,
      created_by: 'admin@vulnify.local',
      state: 'open',
      created_at: Math.floor(Date.now() / 1000),
      is_duplicate: false,
      message: `GitHub issue #${issueNumber} created successfully.`,
    }
    mockGitHubIssuesStore[projectId] = [record, ...store]
    return record
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/github-issues`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'vulnify',
      },
      body: JSON.stringify(request),
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as GitHubIssueRecordResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to create GitHub issue.', { status: response.status })
}

export async function getProjectGitHubIssues(
  projectId: string,
): Promise<GitHubIssueListResponse> {
  if (isMockMode()) {
    const list = mockGitHubIssuesStore[projectId] || []
    return {
      items: list,
      total: list.length,
    }
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/github-issues`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as GitHubIssueListResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to fetch project GitHub issues.', { status: response.status })
}

export async function recordFindingDecision(
  projectId: string,
  findingId: string,
  data: TriageDecisionRequest,
): Promise<TriageDecisionResponse> {
  if (isMockMode()) {
    const list = mockFindingsStore[projectId] || []
    const target = list.find((f) => f.id === findingId)
    if (target) {
      target.status = data.status
      target.triage_justification = data.justification ?? null
      target.triaged_by = 'current_user'
      target.triaged_at = Math.floor(Date.now() / 1000)
    }
    return {
      project_id: projectId,
      finding_id: findingId,
      advisory_id: target?.advisory_id || 'GHSA-mock',
      package_version_id: target?.package_version_id || 'npm:mock@1.0.0',
      status: data.status,
      justification: data.justification ?? null,
      triaged_by: 'current_user',
      triaged_at: Math.floor(Date.now() / 1000),
      review_required: false,
      review_reason: null,
      change_category: null,
      reviewed_at: Math.floor(Date.now() / 1000),
      reviewed_by: 'current_user',
      baseline: null,
    }
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/decision`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'vulnify',
      },
      body: JSON.stringify(data),
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as TriageDecisionResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to record triage decision.', { status: response.status })
}

export async function reviewFindingDecision(
  projectId: string,
  findingId: string,
  data: ReviewDecisionRequest,
): Promise<TriageDecisionResponse> {
  if (isMockMode()) {
    const list = mockFindingsStore[projectId] || []
    const target = list.find((f) => f.id === findingId)
    if (target) {
      if (data.new_status) target.status = data.new_status
      if (data.new_justification) target.triage_justification = data.new_justification
      target.review_required = false
    }
    return {
      project_id: projectId,
      finding_id: findingId,
      advisory_id: target?.advisory_id || 'GHSA-mock',
      package_version_id: target?.package_version_id || 'npm:mock@1.0.0',
      status: data.new_status ?? 'not_affected',
      justification: data.new_justification ?? null,
      triaged_by: 'current_user',
      triaged_at: Math.floor(Date.now() / 1000) - 3600,
      review_required: false,
      review_reason: null,
      change_category: null,
      reviewed_at: Math.floor(Date.now() / 1000),
      reviewed_by: 'current_user',
      baseline: null,
    }
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/review`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'vulnify',
      },
      body: JSON.stringify(data),
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as TriageDecisionResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to review decision.', { status: response.status })
}

export async function getFindingDecision(
  projectId: string,
  findingId: string,
): Promise<ChangeComparisonResponse> {
  if (isMockMode()) {
    return {
      finding_id: findingId,
      has_changed: false,
      review_required: false,
      has_baseline: true,
      category: null,
      reason: null,
      changes: [],
      current_evidence: {},
      baseline: null,
    }
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/decision`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as ChangeComparisonResponse
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to get finding decision.', { status: response.status })
}

export async function detectDecisionChanges(
  projectId: string,
): Promise<{ project_id: string; evaluated_count: number; flagged_count: number; results: ChangeComparisonResponse[] }> {
  if (isMockMode()) {
    return {
      project_id: projectId,
      evaluated_count: 0,
      flagged_count: 0,
      results: [],
    }
  }

  const url = `/api/projects/${encodeURIComponent(projectId)}/decisions/detect-changes`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new ProjectApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as { project_id: string; evaluated_count: number; flagged_count: number; results: ChangeComparisonResponse[] }
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to detect decision changes.', { status: response.status })
}

async function handleErrorResponse(response: Response): Promise<never> {
  if (response.status === 401) {
    notifyUnauthorized()
  }
  const err = await parseApiError(response, 'An unexpected error occurred.')
  throw new ProjectApiError(err.message, {
    status: response.status,
    code: err.code,
    requestId: err.requestId,
  })
}

