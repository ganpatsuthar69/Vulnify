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
} from './types'
import { ApiClientError, isMockMode, parseApiError } from '@/shared/api/client'
import type { ApiClientErrorOptions } from '@/shared/types/api'

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
      packages_with_no_advisories: 7,
      skipped_packages: 0,
      failed_lookups: 0,
      status: 'completed',
      errors: [],
      duration_ms: 185.4,
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


async function handleErrorResponse(response: Response): Promise<never> {
  const err = await parseApiError(response, 'An unexpected error occurred.')
  throw new ProjectApiError(err.message, {
    status: response.status,
    code: err.code,
    requestId: err.requestId,
  })
}

