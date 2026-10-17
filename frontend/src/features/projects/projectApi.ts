import type {
  ImportSummary,
  Project,
  ProjectCreateRequest,
  OsvImportSummary,
  ProjectAdvisory,
  ProjectMatchResponse,
  VulnerabilityFinding,
  PackageVersion,
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

export async function importLockfile(
  projectId: string,
  serviceName: string,
  file: File,
): Promise<ImportSummary> {
  if (isMockMode()) {
    // Generate deterministic mock summary
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
    }
  }

  const formData = new FormData()
  formData.append('service_name', serviceName)
  formData.append('file', file)

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
  throw new ProjectApiError('Failed to import lockfile.', { status: response.status })
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


async function handleErrorResponse(response: Response): Promise<never> {
  const err = await parseApiError(response, 'An unexpected error occurred.')
  throw new ProjectApiError(err.message, {
    status: response.status,
    code: err.code,
    requestId: err.requestId,
  })
}

