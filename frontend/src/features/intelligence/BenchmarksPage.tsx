import { useCallback, useEffect, useState } from 'react'
import {
  AlertCircle,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  Cpu,
  Filter,
  Info,
  Layers,
  Play,
  RefreshCw,
  XCircle,
} from 'lucide-react'
import {
  type BenchmarkRunMetadata,
  type BenchmarkRunResult,
  type CaseComparisonResult,
  deriveCategoryMetrics,
  fetchHistoricalBenchmarkRuns,
  fetchLatestBenchmarkRun,
  fetchBenchmarkRunByFilename,
  fetchGraphPathBenchmark,
  triggerGraphPathBenchmark,
  type GraphPathBenchmarkResult,
  getCategoryDisplayName,
  getSystemDisplayName,
  triggerBenchmarkRun,
} from './benchmarkApi'

export function BenchmarksPage() {
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)
  const [runResult, setRunResult] = useState<BenchmarkRunResult | null>(null)
  const [historicalRuns, setHistoricalRuns] = useState<BenchmarkRunMetadata[]>([])
  const [selectedFilename, setSelectedFilename] = useState<string>('latest')
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL')
  const [expandedCaseId, setExpandedCaseId] = useState<string | null>(null)
  const [runningBenchmark, setRunningBenchmark] = useState<boolean>(false)
  const [graphPathResult, setGraphPathResult] = useState<GraphPathBenchmarkResult | null>(null)
  const [runningGraphPath, setRunningGraphPath] = useState<boolean>(false)

  // 1. Initial Load of Latest Run & History List
  const loadInitialData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [latest, history, gpRes] = await Promise.all([
        fetchLatestBenchmarkRun(),
        fetchHistoricalBenchmarkRuns().catch(() => []),
        fetchGraphPathBenchmark().catch(() => null),
      ])
      setRunResult(latest)
      setHistoricalRuns(history)
      if (gpRes) {
        setGraphPathResult(gpRes)
      }
      setSelectedFilename('latest')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load benchmark results.')
      setRunResult(null)
    } finally {
      setLoading(false)
    }
  }, [])

  const handleTriggerGraphPath = async () => {
    setRunningGraphPath(true)
    try {
      const res = await triggerGraphPathBenchmark(30, 5)
      setGraphPathResult(res)
    } catch {
      // Handled gracefully in UI
    } finally {
      setRunningGraphPath(false)
    }
  }

  useEffect(() => {
    loadInitialData()
  }, [loadInitialData])

  // 2. Handle Historical Run Selection
  const handleSelectRun = async (filename: string) => {
    setSelectedFilename(filename)
    setLoading(true)
    setError(null)
    try {
      if (filename === 'latest') {
        const latest = await fetchLatestBenchmarkRun()
        setRunResult(latest)
      } else {
        const selected = await fetchBenchmarkRunByFilename(filename)
        setRunResult(selected)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to load run '${filename}'.`)
    } finally {
      setLoading(false)
    }
  }

  // 3. Trigger Fresh Benchmark Run
  const handleTriggerRun = async () => {
    setRunningBenchmark(true)
    setError(null)
    try {
      const freshRun = await triggerBenchmarkRun()
      setRunResult(freshRun)
      setSelectedFilename('latest')
      // Refresh history list
      const history = await fetchHistoricalBenchmarkRuns().catch(() => [])
      setHistoricalRuns(history)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Benchmark execution failed.')
    } finally {
      setRunningBenchmark(false)
    }
  }

  // Derive category metrics dynamically from the actual loaded cases
  const cases: CaseComparisonResult[] = runResult?.cases ?? []
  const categoryMetrics = deriveCategoryMetrics(cases)

  const filteredCases = cases.filter(
    (c) => selectedCategory === 'ALL' || c.category === selectedCategory,
  )

  // Top-level summary counts derived from cases
  const totalCases = cases.length
  const graphSuccessCount = cases.filter((c) => c.graph_result.status === 'success').length
  const ragSuccessCount = cases.filter((c) => c.rag_result.status === 'success').length

  const avgGraphLatency =
    totalCases > 0
      ? Math.round(cases.reduce((sum, c) => sum + (c.graph_result.duration_ms || 0), 0) / totalCases * 10) / 10
      : 0
  const avgRagLatency =
    totalCases > 0
      ? Math.round(cases.reduce((sum, c) => sum + (c.rag_result.duration_ms || 0), 0) / totalCases * 10) / 10
      : 0

  return (
    <div className="space-y-6">
      {/* A. Page Header & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-white">Benchmark Results</h1>
            <span className="rounded-full bg-sky-500/15 border border-sky-500/30 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-sky-300">
              US-802 &bull; US-803
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Head-to-head empirical comparison of Vulnify Graph Agent against RAG Baseline using the exact same evidence and model.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Historical Run Selector (if runs exist) */}
          {historicalRuns.length > 0 && (
            <div className="flex items-center gap-1.5 bg-[#0f1822] border border-slate-800 rounded-lg px-2.5 py-1 text-xs">
              <Clock className="h-3.5 w-3.5 text-slate-400" />
              <label htmlFor="run-select" className="sr-only">
                Select benchmark run
              </label>
              <select
                id="run-select"
                value={selectedFilename}
                onChange={(e) => handleSelectRun(e.target.value)}
                className="bg-transparent text-slate-300 font-mono focus:outline-none cursor-pointer"
                disabled={loading || runningBenchmark}
              >
                <option value="latest">Latest Run ({runResult?.run_id ?? 'active'})</option>
                {historicalRuns.map((r) => (
                  <option key={r.filename} value={r.filename}>
                    {r.run_id} ({r.total_cases} cases)
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Re-run button */}
          <button
            type="button"
            onClick={handleTriggerRun}
            disabled={loading || runningBenchmark}
            className="flex items-center gap-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white px-3 py-1.5 text-xs font-semibold transition"
          >
            {runningBenchmark ? (
              <>
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                <span>Running Harness...</span>
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5 fill-current" />
                <span>Run Benchmark</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Graph-Path Query Latency Benchmark Panel (US-903) */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-sky-500/10 border border-sky-500/20 text-sky-400">
              <Layers className="h-4 w-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-white">Graph-Path Query Benchmark</h2>
                <span className="rounded-full bg-indigo-500/15 border border-indigo-500/30 px-2 py-0.5 text-[9px] font-bold text-indigo-300">
                  US-903
                </span>
                {graphPathResult && (
                  <span
                    className={`rounded-full px-2 py-0.5 text-[9px] font-bold ${
                      graphPathResult.target_p95_status === 'PASS'
                        ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-300'
                        : 'bg-rose-500/15 border border-rose-500/30 text-rose-300'
                    }`}
                  >
                    {graphPathResult.target_p95_status}: P95 &lt; 1.0s TARGET
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Evaluates production Cypher path traversal (<code className="text-slate-300 font-mono">[:DEPENDS_ON*1..6]-&gt;[:HAS_VULNERABILITY]</code>) against &ge;5,000 package versions in FalkorDB.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={handleTriggerGraphPath}
            disabled={runningGraphPath}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 px-3 py-1.5 text-xs font-semibold text-slate-200 transition disabled:opacity-50"
          >
            {runningGraphPath ? (
              <>
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                <span>Benchmarking DB...</span>
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5 fill-current" />
                <span>Run Path Benchmark</span>
              </>
            )}
          </button>
        </div>

        {graphPathResult ? (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="rounded-lg bg-[#0b121a] border border-slate-800/80 p-3">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">P95 Latency</div>
              <div className="text-lg font-mono font-bold text-emerald-400 mt-1">
                {typeof graphPathResult.p95_latency_ms === 'number'
                  ? `${graphPathResult.p95_latency_ms.toFixed(2)} ms`
                  : 'N/A'}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">Target: &lt; 1,000.0 ms</div>
            </div>

            <div className="rounded-lg bg-[#0b121a] border border-slate-800/80 p-3">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Median Latency</div>
              <div className="text-lg font-mono font-bold text-sky-400 mt-1">
                {typeof graphPathResult.median_latency_ms === 'number'
                  ? `${graphPathResult.median_latency_ms.toFixed(2)} ms`
                  : 'N/A'}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">50th percentile sample</div>
            </div>

            <div className="rounded-lg bg-[#0b121a] border border-slate-800/80 p-3">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Package Versions</div>
              <div className="text-lg font-mono font-bold text-white mt-1">
                {typeof graphPathResult.package_versions_in_graph === 'number'
                  ? graphPathResult.package_versions_in_graph.toLocaleString()
                  : '0'}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">&ge; 5,000 nodes tested</div>
            </div>

            <div className="rounded-lg bg-[#0b121a] border border-slate-800/80 p-3">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Sample Count</div>
              <div className="text-lg font-mono font-bold text-slate-300 mt-1">
                {graphPathResult.sample_count ?? 0} runs
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">+{graphPathResult.warmup_iterations ?? 0} warmup excluded</div>
            </div>
          </div>
        ) : (
          <div className="rounded-lg bg-[#0b121a] border border-slate-800/80 p-4 text-xs text-slate-400 flex items-center justify-between">
            <span>No graph-path benchmark executed yet. Click &quot;Run Path Benchmark&quot; or execute CLI harness.</span>
            <span className="font-mono text-[11px] text-slate-500">python -m vulnify.benchmarks.graph_path_benchmark</span>
          </div>
        )}
      </div>

      {/* Loading State */}
      {loading && !runResult && (
        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-center space-y-3">
          <RefreshCw className="h-7 w-7 text-sky-400 animate-spin mx-auto" />
          <h3 className="text-sm font-semibold text-white">Loading Measured Results...</h3>
          <p className="text-xs text-slate-400 max-w-sm mx-auto">
            Retrieving real execution records, dependency graph traversals, and baseline metrics.
          </p>
        </div>
      )}

      {/* Error State */}
      {error && !loading && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-5 text-xs text-rose-200 space-y-3">
          <div className="flex items-start gap-3">
            <AlertCircle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <h3 className="font-semibold text-white">Unable to Load Benchmark Results</h3>
              <p className="text-rose-200/90 leading-relaxed">{error}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={loadInitialData}
            className="inline-flex items-center gap-1.5 rounded-md bg-rose-600/30 border border-rose-500/40 text-rose-100 px-3 py-1 text-xs font-medium hover:bg-rose-600/50 transition"
          >
            <RefreshCw className="h-3 w-3" />
            <span>Try Again</span>
          </button>
        </div>
      )}

      {/* Empty State: No Results Yet (AC-2) */}
      {!loading && !error && !runResult && (
        <div className="rounded-xl border border-dashed border-slate-700 bg-[#0f1822] p-12 text-center space-y-4">
          <div className="inline-flex p-3 rounded-full bg-slate-800/80 border border-slate-700 text-slate-400">
            <BarChart3 className="h-6 w-6" />
          </div>
          <div className="space-y-1.5">
            <h3 className="text-base font-bold text-white">No Benchmark Results Yet</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
              No benchmark comparison run exists in the repository yet.
              Per US-803 acceptance criteria, measured counts and comparisons will appear after the US-802 harness has been executed.
            </p>
          </div>
          <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
            <button
              type="button"
              onClick={handleTriggerRun}
              disabled={runningBenchmark}
              className="inline-flex items-center gap-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white px-4 py-2 text-xs font-semibold shadow-sm transition disabled:opacity-50"
            >
              {runningBenchmark ? (
                <>
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  <span>Executing Harness...</span>
                </>
              ) : (
                <>
                  <Play className="h-3.5 w-3.5 fill-current" />
                  <span>Execute Benchmark Harness Now</span>
                </>
              )}
            </button>
          </div>
          <div className="pt-2 text-[11px] text-slate-500 font-mono">
            CLI command: python -m vulnify.benchmarks.runner
          </div>
        </div>
      )}

      {/* Populated State */}
      {!loading && runResult && (
        <div className="space-y-6">
          {/* Small Sample Size Notice (AC-1) */}
          <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-200">
            <div className="flex items-start gap-2.5">
              <Info className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" aria-hidden="true" />
              <div className="space-y-1">
                <span className="font-semibold text-white">Notice on Sample Size & Scientific Scope:</span>
                <p className="text-amber-200/90 leading-relaxed">
                  These results are measured across a hand-verified dataset of <strong>N = {totalCases}</strong> cases
                  (Dataset Version: {runResult.dataset_version}). While statistically limited by design, this targeted benchmark
                  isolates architectural reachability, transitive multi-hop dependencies, disjoint microservice boundaries,
                  and deterministic ranking where graph topology provides structural evidence that vector RAG cannot reliably resolve.
                  Do not interpret small-sample outcomes as universal proof of general performance.
                </p>
              </div>
            </div>
          </div>

          {/* B. Experiment Metadata & Summary Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Run Identification */}
            <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4 space-y-1">
              <div className="flex items-center justify-between text-slate-400 text-xs">
                <span>Experiment Run ID</span>
                <Layers className="h-3.5 w-3.5 text-slate-500" />
              </div>
              <div className="text-sm font-bold text-white font-mono truncate" title={runResult.run_id}>
                {runResult.run_id}
              </div>
              <div className="text-[11px] text-slate-500 truncate">
                Started: {new Date(runResult.started_at).toLocaleTimeString()} &bull; Corpus: {runResult.corpus_id}
              </div>
            </div>

            {/* Shared Model Configuration */}
            <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4 space-y-1">
              <div className="flex items-center justify-between text-slate-400 text-xs">
                <span>Fairness Protocol (Shared Model)</span>
                <Cpu className="h-3.5 w-3.5 text-slate-500" />
              </div>
              <div className="text-sm font-bold text-sky-400 font-mono">
                {runResult.protocol.shared_model}
              </div>
              <div className="text-[11px] text-slate-500">
                Provider: {runResult.protocol.shared_provider} &bull; Temp: {runResult.protocol.temperature}
              </div>
            </div>

            {/* Graph Agent Execution */}
            <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4 space-y-1">
              <div className="flex items-center justify-between text-slate-400 text-xs">
                <span>{getSystemDisplayName(runResult.protocol.graph_system_name)}</span>
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-bold text-white">
                  {graphSuccessCount} / {totalCases}
                </span>
                <span className="text-xs font-semibold text-emerald-400">
                  {totalCases > 0 ? `${Math.round((graphSuccessCount / totalCases) * 100)}%` : '0%'} completed
                </span>
              </div>
              <div className="text-[11px] text-slate-500">
                Avg Latency: {avgGraphLatency}ms per query
              </div>
            </div>

            {/* RAG Baseline Execution */}
            <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4 space-y-1">
              <div className="flex items-center justify-between text-slate-400 text-xs">
                <span>{getSystemDisplayName(runResult.protocol.rag_system_name)}</span>
                <BarChart3 className="h-3.5 w-3.5 text-amber-400" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-bold text-white">
                  {ragSuccessCount} / {totalCases}
                </span>
                <span className="text-xs font-semibold text-amber-400">
                  {totalCases > 0 ? `${Math.round((ragSuccessCount / totalCases) * 100)}%` : '0%'} completed
                </span>
              </div>
              <div className="text-[11px] text-slate-500">
                Avg Latency: {avgRagLatency}ms &bull; Top-{runResult.protocol.top_k_chunks} BM25 Chunks
              </div>
            </div>
          </div>

          {/* D. Category Breakdown Table */}
          <div className="rounded-xl border border-slate-800 bg-[#0f1822] overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-white">Execution Counts & Latency by Category</h2>
                <p className="text-xs text-slate-400">
                  Derived directly from {totalCases} benchmark case records.
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                  <tr>
                    <th scope="col" className="px-4 py-3">Category</th>
                    <th scope="col" className="px-4 py-3 text-center">Cases</th>
                    <th scope="col" className="px-4 py-3">Graph Agent Completed</th>
                    <th scope="col" className="px-4 py-3">Graph Avg Latency</th>
                    <th scope="col" className="px-4 py-3">RAG Baseline Completed</th>
                    <th scope="col" className="px-4 py-3">RAG Avg Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {categoryMetrics.map((row) => (
                    <tr key={row.categoryKey} className="hover:bg-slate-800/20 transition">
                      <td className="px-4 py-3 font-medium text-white">
                        {row.displayName}
                        <div className="text-[10px] text-slate-500 font-mono">{row.categoryKey}</div>
                      </td>
                      <td className="px-4 py-3 text-center text-slate-300 font-mono font-semibold">
                        {row.totalCases}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5 font-semibold text-emerald-400">
                          <CheckCircle2 className="h-3.5 w-3.5" />
                          <span>{row.graphSuccess} / {row.totalCases}</span>
                          {row.graphFailed > 0 && (
                            <span className="text-rose-400 text-[10px]">({row.graphFailed} failed)</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-300">
                        {row.graphAvgDurationMs}ms
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5 font-semibold text-amber-400">
                          <CheckCircle2 className="h-3.5 w-3.5" />
                          <span>{row.ragSuccess} / {row.totalCases}</span>
                          {row.ragFailed > 0 && (
                            <span className="text-rose-400 text-[10px]">({row.ragFailed} failed)</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-300">
                        {row.ragAvgDurationMs}ms
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* E. Per-Case Inspection Section */}
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <Filter className="h-4 w-4 text-slate-400" />
                <h2 className="text-sm font-semibold text-white">Case-by-Case Investigation Evidence</h2>
              </div>

              {/* Category Filter Pills */}
              <div className="flex flex-wrap gap-1.5">
                {['ALL', 'path_exists', 'no_path', 'exposure', 'ranking', 'remediation'].map((catKey) => {
                  const label = catKey === 'ALL' ? 'All Categories' : getCategoryDisplayName(catKey)
                  const isSelected = selectedCategory === catKey
                  return (
                    <button
                      key={catKey}
                      type="button"
                      onClick={() => setSelectedCategory(catKey)}
                      className={`rounded-lg px-2.5 py-1 text-xs font-medium transition cursor-pointer ${
                        isSelected
                          ? 'bg-sky-500 text-white font-semibold'
                          : 'bg-slate-800/80 text-slate-400 hover:text-white hover:bg-slate-700/80'
                      }`}
                    >
                      {label}
                    </button>
                  )
                })}
              </div>
            </div>

            {/* Case List */}
            <div className="space-y-2.5">
              {filteredCases.map((c) => {
                const isExpanded = expandedCaseId === c.case_id

                return (
                  <div
                    key={c.case_id}
                    className="rounded-xl border border-slate-800 bg-[#0f1822] overflow-hidden transition"
                  >
                    {/* Collapsible Header */}
                    <button
                      type="button"
                      onClick={() => setExpandedCaseId(isExpanded ? null : c.case_id)}
                      className="w-full p-4 flex items-start justify-between text-left hover:bg-slate-800/20 transition cursor-pointer"
                    >
                      <div className="space-y-1 pr-4">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-sky-400">{c.case_id}</span>
                          <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-slate-300 font-medium">
                            {getCategoryDisplayName(c.category)}
                          </span>
                          <span className="text-[10px] text-slate-500 uppercase">{c.difficulty}</span>
                        </div>
                        <p className="text-xs font-medium text-white">{c.question}</p>
                      </div>

                      <div className="flex items-center gap-3 shrink-0">
                        <div className="flex items-center gap-2 text-xs">
                          <span className="text-slate-400 text-[11px]">Graph:</span>
                          {c.graph_result.status === 'success' ? (
                            <span className="text-emerald-400 font-mono text-[11px] font-semibold">
                              {c.graph_result.duration_ms}ms
                            </span>
                          ) : (
                            <XCircle className="h-3.5 w-3.5 text-rose-400" />
                          )}

                          <span className="text-slate-400 text-[11px] ml-1">RAG:</span>
                          {c.rag_result.status === 'success' ? (
                            <span className="text-amber-400 font-mono text-[11px] font-semibold">
                              {c.rag_result.duration_ms}ms
                            </span>
                          ) : (
                            <XCircle className="h-3.5 w-3.5 text-rose-400" />
                          )}
                        </div>

                        {isExpanded ? (
                          <ChevronUp className="h-4 w-4 text-slate-400" />
                        ) : (
                          <ChevronDown className="h-4 w-4 text-slate-400" />
                        )}
                      </div>
                    </button>

                    {/* Expanded Detail Inspection */}
                    {isExpanded && (
                      <div className="p-4 border-t border-slate-800/80 bg-slate-900/40 space-y-4 text-xs">
                        {/* Ground Truth Expected Conclusion */}
                        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 space-y-1">
                          <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                            Verified Expected Ground Truth (US-801)
                          </span>
                          <p className="text-slate-200 leading-relaxed">{c.expected_conclusion}</p>
                        </div>

                        {/* Side-by-Side Comparison */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          {/* Vulnify Graph Agent Output */}
                          <div className="rounded-lg border border-emerald-500/20 bg-emerald-950/10 p-3 space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="font-semibold text-emerald-400 flex items-center gap-1.5">
                                <CheckCircle2 className="h-3.5 w-3.5" />
                                <span>Vulnify Graph Agent</span>
                              </span>
                              <span className="font-mono text-[11px] text-slate-400">
                                {c.graph_result.duration_ms}ms
                              </span>
                            </div>

                            {/* Safe text rendering */}
                            <div className="text-slate-300 whitespace-pre-wrap leading-relaxed text-[11px] bg-black/20 rounded p-2.5">
                              {c.graph_result.answer || 'No answer generated.'}
                            </div>

                            {/* Evidence References */}
                            {c.graph_result.evidence_references?.length > 0 && (
                              <div className="text-[10px] text-slate-400 space-y-1">
                                <span className="text-slate-500 font-medium">Evidence Citations:</span>
                                <div className="flex flex-wrap gap-1 font-mono">
                                  {c.graph_result.evidence_references.map((ref, idx) => (
                                    <span key={idx} className="bg-slate-800/80 px-1.5 py-0.5 rounded text-slate-300">
                                      {ref}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>

                          {/* RAG Baseline Output */}
                          <div className="rounded-lg border border-amber-500/20 bg-amber-950/10 p-3 space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="font-semibold text-amber-400 flex items-center gap-1.5">
                                <BarChart3 className="h-3.5 w-3.5" />
                                <span>RAG Baseline (BM25 Chunks)</span>
                              </span>
                              <span className="font-mono text-[11px] text-slate-400">
                                {c.rag_result.duration_ms}ms
                              </span>
                            </div>

                            {/* Safe text rendering */}
                            <div className="text-slate-300 whitespace-pre-wrap leading-relaxed text-[11px] bg-black/20 rounded p-2.5">
                              {c.rag_result.answer || 'No answer generated.'}
                            </div>

                            {/* Evidence References */}
                            {c.rag_result.evidence_references?.length > 0 && (
                              <div className="text-[10px] text-slate-400 space-y-1">
                                <span className="text-slate-500 font-medium">Retrieved Chunks:</span>
                                <div className="flex flex-wrap gap-1 font-mono">
                                  {c.rag_result.evidence_references.map((ref, idx) => (
                                    <span key={idx} className="bg-slate-800/80 px-1.5 py-0.5 rounded text-slate-300">
                                      {ref}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
