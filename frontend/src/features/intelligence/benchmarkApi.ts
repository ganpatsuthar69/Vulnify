/**
 * Benchmark API Client, Types, and Pure Selectors (US-802 / US-803).
 *
 * Interfaces with Vulnify's FastAPI backend to retrieve real benchmark results,
 * calculate category counts dynamically, and manage historical experiment runs.
 */

import { parseApiError } from '@/shared/api/client'

export interface ComparisonProtocol {
  protocol_version: string
  graph_system_name: string
  rag_system_name: string
  shared_model: string
  shared_provider: string
  temperature: number
  max_tokens: number
  retrieval_strategy: string
  top_k_chunks: number
}

export interface CategorySummaryMetrics {
  total_cases: number
  graph_success_count: number
  rag_success_count: number
  graph_avg_duration_ms: number
  rag_avg_duration_ms: number
}

export interface RunSummary {
  total_cases: number
  graph_success_count: number
  rag_success_count: number
  graph_error_count: number
  rag_error_count: number
  graph_avg_duration_ms: number
  rag_avg_duration_ms: number
  by_category: Record<string, CategorySummaryMetrics>
}

export type ExecutionStatus = 'success' | 'failed' | 'error' | 'skipped'

export interface SystemExecutionResult {
  system_id: string
  status: ExecutionStatus
  answer: string
  evidence_references: string[]
  retrieval_metadata: Record<string, unknown>
  duration_ms: number
  tokens_used?: number | null
  error_message?: string | null
}

export interface CaseComparisonResult {
  case_id: string
  category: string
  difficulty: string
  question: string
  expected_conclusion: string
  graph_result: SystemExecutionResult
  rag_result: SystemExecutionResult
}

export interface BenchmarkRunResult {
  schema_version: string
  run_id: string
  dataset_version: string
  corpus_id: string
  started_at: string
  completed_at: string
  protocol: ComparisonProtocol
  summary: RunSummary
  cases: CaseComparisonResult[]
}

export interface BenchmarkRunMetadata {
  filename: string
  run_id: string
  created_at: string
  dataset_version: string
  total_cases: number
  graph_success_count: number
  rag_success_count: number
}

export interface DerivedCategoryCount {
  categoryKey: string
  displayName: string
  totalCases: number
  graphSuccess: number
  graphFailed: number
  graphOther: number
  ragSuccess: number
  ragFailed: number
  ragOther: number
  graphAvgDurationMs: number
  ragAvgDurationMs: number
}

export const CATEGORY_DISPLAY_MAP: Record<string, string> = {
  path_exists: 'Path Existence',
  no_path: 'No-Path Negative',
  exposure: 'Architectural Exposure',
  ranking: 'Deterministic Ranking',
  remediation: 'Remediation Guidance',
}

export const SYSTEM_DISPLAY_MAP: Record<string, string> = {
  graph_agent: 'Vulnify Graph Agent',
  'vulnify-graph-agent': 'Vulnify Graph Agent',
  rag_baseline: 'RAG Baseline',
  'text-rag-baseline': 'RAG Baseline',
}

export function getCategoryDisplayName(categoryKey: string): string {
  return CATEGORY_DISPLAY_MAP[categoryKey] ?? categoryKey
}

export function getSystemDisplayName(systemId: string): string {
  return SYSTEM_DISPLAY_MAP[systemId] ?? systemId
}

/**
 * Pure selector: Derives per-category execution counts and duration averages
 * directly from actual case records without hardcoding.
 */
export function deriveCategoryMetrics(cases: CaseComparisonResult[]): DerivedCategoryCount[] {
  const groups: Record<string, CaseComparisonResult[]> = {}

  for (const c of cases) {
    const cat = c.category || 'unknown'
    if (!groups[cat]) {
      groups[cat] = []
    }
    groups[cat].push(c)
  }

  const result: DerivedCategoryCount[] = []

  for (const [catKey, groupCases] of Object.entries(groups)) {
    let graphSuccess = 0
    let graphFailed = 0
    let graphOther = 0
    let graphTotalMs = 0

    let ragSuccess = 0
    let ragFailed = 0
    let ragOther = 0
    let ragTotalMs = 0

    for (const c of groupCases) {
      // Graph system counts
      if (c.graph_result.status === 'success') {
        graphSuccess++
      } else if (c.graph_result.status === 'failed') {
        graphFailed++
      } else {
        graphOther++
      }
      graphTotalMs += c.graph_result.duration_ms || 0

      // RAG baseline counts
      if (c.rag_result.status === 'success') {
        ragSuccess++
      } else if (c.rag_result.status === 'failed') {
        ragFailed++
      } else {
        ragOther++
      }
      ragTotalMs += c.rag_result.duration_ms || 0
    }

    const count = groupCases.length
    result.push({
      categoryKey: catKey,
      displayName: getCategoryDisplayName(catKey),
      totalCases: count,
      graphSuccess,
      graphFailed,
      graphOther,
      ragSuccess,
      ragFailed,
      ragOther,
      graphAvgDurationMs: count > 0 ? Math.round((graphTotalMs / count) * 10) / 10 : 0,
      ragAvgDurationMs: count > 0 ? Math.round((ragTotalMs / count) * 10) / 10 : 0,
    })
  }

  // Stable ordering
  const preferredOrder = ['path_exists', 'no_path', 'exposure', 'ranking', 'remediation']
  result.sort((a, b) => {
    const idxA = preferredOrder.indexOf(a.categoryKey)
    const idxB = preferredOrder.indexOf(b.categoryKey)
    if (idxA !== -1 && idxB !== -1) return idxA - idxB
    if (idxA !== -1) return -1
    if (idxB !== -1) return 1
    return a.displayName.localeCompare(b.displayName)
  })

  return result
}

/**
 * Fetch the latest benchmark comparison run.
 * Returns null if no run has been executed yet (HTTP 404).
 */
export async function fetchLatestBenchmarkRun(): Promise<BenchmarkRunResult | null> {
  const resp = await fetch('/api/benchmarks/results/latest', {
    method: 'GET',
    headers: { Accept: 'application/json' },
  })

  if (resp.status === 404) {
    return null
  }

  if (!resp.ok) {
    const err = await parseApiError(resp, 'Failed to retrieve latest benchmark results.')
    throw new Error(err.message)
  }

  return (await resp.json()) as BenchmarkRunResult
}

/**
 * List historical benchmark run metadata for the run selector.
 */
export async function fetchHistoricalBenchmarkRuns(): Promise<BenchmarkRunMetadata[]> {
  const resp = await fetch('/api/benchmarks/results', {
    method: 'GET',
    headers: { Accept: 'application/json' },
  })

  if (!resp.ok) {
    const err = await parseApiError(resp, 'Failed to list historical benchmark runs.')
    throw new Error(err.message)
  }

  return (await resp.json()) as BenchmarkRunMetadata[]
}

/**
 * Fetch a specific historical benchmark run by artifact filename.
 */
export async function fetchBenchmarkRunByFilename(filename: string): Promise<BenchmarkRunResult> {
  const resp = await fetch(`/api/benchmarks/results/run/${encodeURIComponent(filename)}`, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  })

  if (!resp.ok) {
    const err = await parseApiError(resp, `Failed to load benchmark run '${filename}'.`)
    throw new Error(err.message)
  }

  return (await resp.json()) as BenchmarkRunResult
}
export interface TriggerBenchmarkParams {
  category?: string | null
  dry_run?: boolean
  llm_provider?: string
  llm_model?: string
  temperature?: number
}

/**
 * Trigger a new benchmark comparison run.
 * If llm_provider or llm_model are omitted, the backend dynamically resolves
 * them from its configured environment / database settings without hardcoded defaults.
 */
export async function triggerBenchmarkRun(
  params?: TriggerBenchmarkParams,
): Promise<BenchmarkRunResult> {
  const payload: Record<string, unknown> = {
    category: params?.category ?? null,
    dry_run: params?.dry_run ?? false,
  }

  if (params?.llm_provider) {
    payload.llm_provider = params.llm_provider
  }
  if (params?.llm_model) {
    payload.llm_model = params.llm_model
  }
  if (params?.temperature !== undefined) {
    payload.temperature = params.temperature
  }

  const resp = await fetch('/api/benchmarks/run', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-Requested-With': 'vulnify',
    },
    body: JSON.stringify(payload),
  })

  if (!resp.ok) {
    const err = await parseApiError(resp, 'Failed to trigger benchmark run.')
    throw new Error(err.message)
  }

  return (await resp.json()) as BenchmarkRunResult
}
