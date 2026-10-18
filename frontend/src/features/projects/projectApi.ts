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
  FindingListResponse,
  ProjectService,
  FindingFilters,
  FindingSummaryResponse,
  FindingDetail,
  FindingPathsResponse,
  ProjectExposurePathsResponse,
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
import { ApiClientError, getApiUrl, parseApiError } from '@/shared/api/client'
import type { ApiClientErrorOptions } from '@/shared/types/api'
import { notifyUnauthorized } from '@/features/auth/authApi'
import type { ExplorerGraph, GraphRequest } from '@/features/graph/types'

export class ProjectApiError extends ApiClientError {
  constructor(
    message: string,
    options?: ApiClientErrorOptions,
  ) {
    super(message, options)
    this.name = 'ProjectApiError'
  }
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

export async function getProjectGraph(
  projectId: string,
  params: GraphRequest = {},
  signal?: AbortSignal,
): Promise<ExplorerGraph> {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') query.set(key, String(value))
  }
  let response: Response
  try {
    response = await fetch(getApiUrl(`/api/projects/${encodeURIComponent(projectId)}/graph?${query}`), {
      credentials: 'include',
      signal,
    })
  } catch (error) {
    if (signal?.aborted) throw error
    throw new ProjectApiError('Cannot reach the graph server.', { isNetworkError: true })
  }
  if (response.ok) return (await response.json()) as ExplorerGraph
  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to load graph relationships.', { status: response.status })
}

export async function listProjects(): Promise<Project[]> {
  let response: Response
  try {
    response = await fetch(getApiUrl('/api/projects'), {
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
  let response: Response
  try {
    response = await fetch(getApiUrl('/api/projects'), {
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
  let response: Response
  try {
    response = await fetch(getApiUrl('/api/projects/ecosystem-capabilities'), {
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
    response = await fetch(getApiUrl(`/api/projects/${encodeURIComponent(projectId)}/dependencies/import`), {
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

export async function importAdvisories(
  projectId: string,
  forceRefresh: boolean = false,
): Promise<OsvImportSummary> {
  const queryParam = forceRefresh ? '?force_refresh=true' : ''
  let response: Response
  try {
    response = await fetch(
      getApiUrl(`/api/projects/${encodeURIComponent(projectId)}/advisories/import${queryParam}`),
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          'X-Requested-With': 'vulnify',
        },
      },
    )
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
  let response: Response
  try {
    response = await fetch(getApiUrl(`/api/projects/${encodeURIComponent(projectId)}/advisories`), {
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

export async function getProjectPackages(projectId: string): Promise<PackageVersion[]> {
  let response: Response
  try {
    response = await fetch(getApiUrl(`/api/projects/${encodeURIComponent(projectId)}/packages`), {
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
  let response: Response
  try {
    response = await fetch(getApiUrl(`/api/projects/${encodeURIComponent(projectId)}/vulnerabilities/match`), {
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
  let response: Response
  try {
    response = await fetch(getApiUrl(`/api/projects/${encodeURIComponent(projectId)}/vulnerabilities`), {
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
  const searchParams = new URLSearchParams()
  if (params?.page) searchParams.set('page', String(params.page))
  if (params?.page_size) searchParams.set('page_size', String(params.page_size))
  if (params?.status) searchParams.set('status', params.status)
  if (params?.job_type) searchParams.set('job_type', params.job_type)
  if (params?.service_name) searchParams.set('service_name', params.service_name)

  const query = searchParams.toString() ? `?${searchParams.toString()}` : ''
  let response: Response
  try {
    response = await fetch(getApiUrl(`/api/projects/${encodeURIComponent(projectId)}/jobs${query}`), {
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
  let response: Response
  try {
    response = await fetch(
      getApiUrl(`/api/projects/${encodeURIComponent(projectId)}/jobs/${encodeURIComponent(jobId)}`),
      {
        method: 'GET',
        credentials: 'include',
        headers: {
          'X-Requested-With': 'vulnify',
        },
      },
    )
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
  let response: Response
  try {
    response = await fetch(
      getApiUrl(`/api/projects/${encodeURIComponent(projectId)}/jobs/${encodeURIComponent(jobId)}/retry`),
      {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'vulnify',
        },
      },
    )
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
  let response: Response
  try {
    response = await fetch(getApiUrl(`/api/projects/${encodeURIComponent(projectId)}/services`), {
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

export async function getProjectFindings(
  projectId: string,
  params?: FindingFilters,
): Promise<FindingListResponse> {
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
    response = await fetch(getApiUrl(url), {
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
  const queryParams = new URLSearchParams()
  if (params?.priority) queryParams.set('priority', params.priority)
  if (params?.service_id) queryParams.set('service_id', params.service_id)
  if (params?.status) queryParams.set('status', params.status)
  if (params?.search) queryParams.set('search', params.search)

  const queryString = queryParams.toString()
  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/summary${queryString ? `?${queryString}` : ''}`

  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const queryParams = new URLSearchParams()
  if (params?.max_depth !== undefined) queryParams.set('max_depth', String(params.max_depth))
  if (params?.limit !== undefined) queryParams.set('limit', String(params.limit))
  const queryString = queryParams.toString()

  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/paths${queryString ? `?${queryString}` : ''}`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const queryParams = new URLSearchParams()
  if (params?.findingId) queryParams.set('finding_id', params.findingId)
  if (params?.serviceId) queryParams.set('service_id', params.serviceId)
  if (params?.limit !== undefined) queryParams.set('limit', String(params.limit))
  const queryString = queryParams.toString()

  const url = `/api/projects/${encodeURIComponent(projectId)}/exposure-paths${queryString ? `?${queryString}` : ''}`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const queryParams = new URLSearchParams()
  if (params?.limit !== undefined) queryParams.set('limit', String(params.limit))
  const queryString = queryParams.toString()

  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/exposure-paths${queryString ? `?${queryString}` : ''}`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = `/api/projects/${encodeURIComponent(projectId)}/data-quality`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/upgrade-candidates`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = `/api/projects/${encodeURIComponent(projectId)}/upgrade-candidates`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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

export async function simulateFix(
  projectId: string,
  request: SimulationRequest,
): Promise<SimulationResponse> {
  const url = `/api/projects/${encodeURIComponent(projectId)}/simulations`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = `/api/projects/${encodeURIComponent(projectId)}/simulations`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = `/api/projects/${encodeURIComponent(projectId)}/simulations/${encodeURIComponent(simulationId)}`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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

export async function getGitHubStatus(
  projectId: string,
): Promise<GitHubIntegrationStatusResponse> {
  const url = `/api/projects/${encodeURIComponent(projectId)}/github/status`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = projectId
    ? `/api/projects/${encodeURIComponent(projectId)}/github/config`
    : '/api/admin/github-config'

  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = data.project_id
    ? `/api/projects/${encodeURIComponent(data.project_id)}/github/config`
    : '/api/admin/github-config'
  const method = data.project_id ? 'PUT' : 'POST'

  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = data.project_id
    ? `/api/projects/${encodeURIComponent(data.project_id)}/github/validate`
    : '/api/admin/github-config/validate'

  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/github-issues/preview`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/github-issues`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = `/api/projects/${encodeURIComponent(projectId)}/github-issues`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/decision`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/review`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = `/api/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/decision`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
  const url = `/api/projects/${encodeURIComponent(projectId)}/decisions/detect-changes`
  let response: Response
  try {
    response = await fetch(getApiUrl(url), {
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
    return (await response.json()) as {
      project_id: string
      evaluated_count: number
      flagged_count: number
      results: ChangeComparisonResponse[]
    }
  }

  await handleErrorResponse(response)
  throw new ProjectApiError('Failed to detect decision changes.', { status: response.status })
}
