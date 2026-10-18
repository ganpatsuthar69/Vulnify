import { useState, useEffect } from 'react'
import {
  ArrowLeft,
  ArrowRight,
  ShieldAlert,
  ExternalLink,
  Loader2,
  CheckCircle2,
  Route,
  GitPullRequest,
  AlertTriangle,
  RefreshCw,
  Clock,
  Bot,
  Database,
  RotateCcw,
} from 'lucide-react'
import { Link, useParams, useNavigate } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import { getProjectFindingDetail, ProjectApiError } from '@/features/projects/projectApi'
import type { FindingDetail } from '@/features/projects/types'
import { DependencyPathVisualizer } from '@/features/graph/DependencyPathVisualizer'
import { DataQualityBanner } from '@/shared/components/DataQualityBanner'
import { FindingUpgradeCandidatesSection } from '@/features/remediation/FindingUpgradeCandidatesSection'
import { getAgentRunsByFinding, type AgentRunSummary } from '@/features/intelligence/agentApi'
import { TraceDrawer } from '@/features/intelligence/TraceDrawer'

export function FindingDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { activeProject } = useProjects()
  const navigate = useNavigate()

  const [finding, setFinding] = useState<FindingDetail | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isNotFound, setIsNotFound] = useState(false)
  const [reloadTrigger, setReloadTrigger] = useState(0)

  // Stored Agent Traces (US-603)
  const [findingRuns, setFindingRuns] = useState<AgentRunSummary[]>([])
  const [isLoadingRuns, setIsLoadingRuns] = useState(false)
  const [selectedTraceRunId, setSelectedTraceRunId] = useState<string | null>(null)
  const [isTraceDrawerOpen, setIsTraceDrawerOpen] = useState(false)

  useEffect(() => {
    let isMounted = true

    async function fetchFinding() {
      if (!activeProject || !id) return
      setIsLoading(true)
      setError(null)
      setIsNotFound(false)

      try {
        const data = await getProjectFindingDetail(activeProject.id, id)
        if (isMounted) {
          setFinding(data)
        }
      } catch (err) {
        if (!isMounted) return
        if (err instanceof ProjectApiError && err.status === 404) {
          setIsNotFound(true)
          setError(
            err.message ||
              `Finding "${id}" was not found in project "${activeProject.name}".`,
          )
        } else if (err instanceof ProjectApiError) {
          setError(err.message)
        } else {
          setError('Failed to fetch finding details from FalkorDB.')
        }
      } finally {
        if (isMounted) {
          setIsLoading(false)
        }
      }
    }

    void fetchFinding()

    return () => {
      isMounted = false
    }
  }, [activeProject, id, reloadTrigger])

  useEffect(() => {
    let isMounted = true
    if (!activeProject || !id) return

    setIsLoadingRuns(true)
    getAgentRunsByFinding(activeProject.id, id)
      .then((runs) => {
        if (isMounted) setFindingRuns(runs)
      })
      .catch((err) => {
        console.warn('Failed to load agent runs for finding:', err)
        if (isMounted) setFindingRuns([])
      })
      .finally(() => {
        if (isMounted) setIsLoadingRuns(false)
      })

    return () => {
      isMounted = false
    }
  }, [activeProject, id, reloadTrigger])

  const formatRetrievedDate = (timestamp?: number | null) => {
    if (!timestamp) return 'Timestamp unavailable'
    try {
      const date = new Date(timestamp * 1000)
      return isNaN(date.getTime()) ? 'Invalid timestamp' : date.toUTCString()
    } catch {
      return 'Timestamp unavailable'
    }
  }

  // 1. Loading State
  if (isLoading) {
    return (
      <div
        className="flex flex-col items-center justify-center p-16 text-slate-400"
        role="status"
        aria-live="polite"
      >
        <Loader2 className="h-8 w-8 animate-spin text-sky-400" aria-hidden="true" />
        <span className="mt-4 text-xs font-medium text-slate-300">
          Loading finding evidence...
        </span>
      </div>
    )
  }

  // 2. Not Found State (AC-3)
  if (isNotFound) {
    return (
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
        <ShieldAlert className="mx-auto h-10 w-10 text-amber-400" aria-hidden="true" />
        <h2 className="mt-4 text-lg font-bold text-white">Finding Not Found</h2>
        <p className="mt-2 text-slate-300 max-w-md mx-auto">
          {error ||
            `Finding "${id}" does not exist in the active project "${activeProject?.name}".`}
        </p>
        <p className="mt-1 text-slate-500">
          The requested finding ID or advisory may have been resolved, removed, or the link is invalid.
        </p>
        <div className="mt-6">
          <Link
            to="/findings"
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-white shadow-sm hover:bg-sky-400 transition-colors focus:outline-none focus:ring-2 focus:ring-sky-500"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Back to Findings</span>
          </Link>
        </div>
      </div>
    )
  }

  // 3. Error / Server Failure State
  if (error || !finding) {
    return (
      <div className="rounded-xl border border-rose-900/40 bg-[#170e13] p-10 text-center text-xs text-slate-400">
        <AlertTriangle className="mx-auto h-10 w-10 text-rose-400" aria-hidden="true" />
        <h2 className="mt-3 text-base font-bold text-white">Unable to Load Finding</h2>
        <p className="mt-1 text-rose-300">{error || 'An unexpected database error occurred.'}</p>
        <div className="mt-5 flex items-center justify-center gap-3">
          <button
            type="button"
            onClick={() => setReloadTrigger((prev) => prev + 1)}
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Retry</span>
          </button>
          <Link
            to="/findings"
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition-colors"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Back to Findings</span>
          </Link>
        </div>
      </div>
    )
  }

  // 4. Populated Finding Detail View (AC-1 & AC-2)
  const severityUpper = (finding.severity || 'UNKNOWN').toUpperCase()
  const severityBadgeClass =
    severityUpper === 'CRITICAL'
      ? 'border-red-500/40 bg-red-500/15 text-red-300'
      : severityUpper === 'HIGH'
      ? 'border-orange-500/40 bg-orange-500/15 text-orange-300'
      : severityUpper === 'MODERATE' || severityUpper === 'MEDIUM'
      ? 'border-amber-500/40 bg-amber-500/15 text-amber-300'
      : 'border-slate-600 bg-slate-700/50 text-slate-300'

  return (
    <div className="space-y-6">
      {/* Top Bar with Back Link and Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <Link
            to="/findings"
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-sky-400 hover:text-sky-300 transition-colors mb-2 focus:outline-none focus:underline"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Back to Findings</span>
          </Link>

          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-bold font-mono text-white tracking-tight">
              {finding.advisory_id}
            </h1>

            {/* Severity Badge */}
            <span
              className={`rounded px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider border ${severityBadgeClass}`}
            >
              {finding.severity || 'UNKNOWN'}
            </span>

            {/* Priority Band */}
            <span className="rounded border border-slate-700 bg-slate-800/80 px-2 py-0.5 text-xs font-medium text-slate-300">
              Priority: <strong className="text-white capitalize">{finding.priority}</strong>
              {finding.scoring_version && (
                <span className="ml-1 text-[10px] text-slate-400 font-mono">({finding.scoring_version})</span>
              )}
            </span>

            {/* Triage Status */}
            <span className="rounded border border-slate-700 bg-slate-800/80 px-2 py-0.5 text-xs font-medium text-slate-300">
              Status: <strong className="text-white capitalize">{finding.status}</strong>
            </span>

            {/* US-402: Needs Review Badge */}
            {finding.review_required && (
              <span className="rounded bg-rose-500/20 border border-rose-500/40 px-2.5 py-0.5 text-xs font-semibold text-rose-300 flex items-center gap-1">
                <AlertTriangle className="h-3 w-3" />
                <span>Needs Review</span>
              </span>
            )}
          </div>

          {/* Finding ID and Aliases */}
          <div className="mt-1.5 flex flex-wrap items-center gap-3 text-xs text-slate-400 font-mono">
            <span>Finding ID: {finding.id}</span>
            {finding.aliases && finding.aliases.length > 0 && (
              <span>• Aliases: {finding.aliases.join(', ')}</span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => {
              if (findingRuns.length > 0) {
                setSelectedTraceRunId(findingRuns[0]!.id)
                setIsTraceDrawerOpen(true)
              } else {
                navigate('/investigation')
              }
            }}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-700 hover:text-white transition-colors focus:outline-none focus:ring-2 focus:ring-slate-600"
            title={
              findingRuns.length > 0
                ? `Inspect ${findingRuns.length} stored agent traces for this finding`
                : 'No agent traces found for this finding yet'
            }
          >
            <Database className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
            <span>Investigation Traces ({findingRuns.length})</span>
          </button>

          <Link
            to={`/github-issues?finding=${encodeURIComponent(finding.id)}`}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-2 text-xs font-semibold text-white shadow-sm hover:bg-sky-400 transition-colors focus:outline-none focus:ring-2 focus:ring-sky-500"
          >
            <GitPullRequest className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Preview Remediation Issue</span>
          </Link>

          {finding.source_url ? (
            <a
              href={finding.source_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-700 hover:text-white transition-colors focus:outline-none focus:ring-2 focus:ring-slate-600"
            >
              <span>Source Advisory</span>
              <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
            </a>
          ) : null}
        </div>
      </div>

      {/* US-402: Contextual Review Required Banner */}
      {finding.review_required && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-950/25 p-5 shadow-lg flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
            <div>
              <h2 className="text-sm font-bold text-rose-200">
                Decision Requires Review &bull; Underlying Evidence Changed
              </h2>
              <p className="mt-1 text-xs text-rose-200/90 leading-relaxed">
                {finding.review_reason || 'Evidence supporting the previous decision has changed since it was recorded.'}
              </p>
              {finding.triage_justification && (
                <div className="mt-2 text-xs text-slate-300">
                  <strong>Prior recorded justification:</strong> &ldquo;{finding.triage_justification}&rdquo;
                  {finding.triaged_by && (
                    <span className="text-slate-400 ml-1.5">(recorded by {finding.triaged_by})</span>
                  )}
                </div>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Link
              to="/review"
              className="rounded-lg bg-rose-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-rose-500 transition-colors shadow-sm"
            >
              Open Review Queue
            </Link>
          </div>
        </div>
      )}

      {/* US-207: Contextual Data Quality & Analysis Limits Banner */}
      {finding.warnings && finding.warnings.length > 0 && (
        <DataQualityBanner warnings={finding.warnings} />
      )}

      {/* Advisory Overview Card: AC-1 & AC-2 (Rendered as pure plain-text, no HTML execution) */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white">Advisory Summary</h2>
        {/* Render summary safely as plain text */}
        <p className="text-xs text-slate-200 leading-relaxed font-medium whitespace-pre-wrap break-words">
          {finding.advisory_summary || 'No advisory summary provided.'}
        </p>

        {finding.advisory_details ? (
          <div>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Advisory Details (Plain Text)
            </h3>
            {/* Preserving whitespace and line breaks securely with CSS; React guarantees HTML escaping */}
            <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-xs text-slate-300 whitespace-pre-wrap font-mono leading-relaxed max-h-80 overflow-y-auto break-words select-text">
              {finding.advisory_details}
            </div>
          </div>
        ) : null}
      </div>

      {/* Priority Band & Decision Reasons Card */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <h2 className="text-sm font-bold text-white">Priority Ranking &amp; Evidence</h2>
            <span
              className={`rounded px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider ${
                finding.priority.toLowerCase() === 'highest'
                  ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                  : finding.priority.toLowerCase() === 'high'
                  ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                  : finding.priority.toLowerCase() === 'medium'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                  : finding.priority.toLowerCase() === 'low'
                  ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                  : 'bg-slate-700/40 text-slate-300 border border-slate-600'
              }`}
            >
              {finding.priority} Priority
            </span>
          </div>
          {finding.scoring_version && (
            <span className="text-[11px] font-mono text-slate-400 bg-slate-800/80 border border-slate-700/60 px-2 py-0.5 rounded self-start sm:self-auto">
              Policy Version: {finding.scoring_version}
            </span>
          )}
        </div>

        <p className="text-xs text-slate-300">
          Priority is deterministically computed from architectural reachability, advisory severity, and remediation signals according to <span className="font-mono text-slate-200">docs/scoring.md</span>. Missing signals are treated as unknown, not zero risk.
        </p>

        {finding.priority_reasons && finding.priority_reasons.length > 0 ? (
          <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4">
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
              Decision Reasons:
            </h3>
            <ul className="space-y-1.5 text-xs text-slate-200">
              {finding.priority_reasons.map((reason, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="mt-1 h-1.5 w-1.5 rounded-full bg-sky-400 shrink-0" />
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>

      {/* Evidence & Version Matching Engine Results */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* AC-1: Match Verification & Evidence */}
        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-4">
          <div className="flex items-center gap-2 text-sm font-bold text-white">
            <CheckCircle2 className="h-4 w-4 text-emerald-400" aria-hidden="true" />
            <span>Version Match Evidence</span>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Target Package:</span>
              <span className="font-semibold text-white font-mono">{finding.package_name}</span>
            </div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Matched Version:</span>
              <span className="font-mono font-semibold text-sky-400">
                {finding.package_version}
              </span>
            </div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Ecosystem:</span>
              <span className="font-semibold text-slate-300 uppercase">{finding.ecosystem}</span>
            </div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Affected Version Range:</span>
              <span className="font-mono text-amber-300 font-medium">
                {finding.matched_range ?? 'Unspecified'}
              </span>
            </div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Fixed Version:</span>
              <span className="font-mono font-bold text-emerald-400">
                {finding.fixed_version ? `>= ${finding.fixed_version}` : 'No known fix'}
              </span>
            </div>
            <div>
              <span className="text-slate-400 block mb-1">Why Version Matched:</span>
              <div className="rounded-lg bg-[#0b121a] p-3 text-slate-300 font-medium border border-slate-800 whitespace-pre-wrap break-words">
                {finding.match_reason ||
                  (finding.reason_code ? `Matched rule: ${finding.reason_code}` : 'Matched version constraint.')}
              </div>
            </div>
          </div>
        </div>

        {/* Provenance & Advisory Metadata */}
        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-4">
          <div className="flex items-center gap-2 text-sm font-bold text-white">
            <Clock className="h-4 w-4 text-sky-400" aria-hidden="true" />
            <span>Advisory Provenance &amp; Metadata</span>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Advisory ID:</span>
              <span className="font-mono text-white font-semibold">{finding.advisory_id}</span>
            </div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Retrieved At:</span>
              <span className="text-slate-300 font-mono">
                {formatRetrievedDate(finding.retrieved_at)}
              </span>
            </div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Source Link:</span>
              {finding.source_url ? (
                <a
                  href={finding.source_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-sky-400 hover:text-sky-300 underline inline-flex items-center gap-1 truncate max-w-[200px]"
                >
                  <span className="truncate">{finding.source_url}</span>
                  <ExternalLink className="h-3 w-3 shrink-0" aria-hidden="true" />
                </a>
              ) : (
                <span className="text-slate-500">Not provided</span>
              )}
            </div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Associated Service:</span>
              <span className="font-semibold text-white">{finding.service_name}</span>
            </div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Dependency Path Depth:</span>
              <span className="font-mono text-slate-300">
                {finding.path_depth !== null && finding.path_depth !== undefined
                  ? `${finding.path_depth} hop${finding.path_depth > 1 ? 's' : ''} (${finding.path_depth === 1 ? 'direct dependency' : 'transitive dependency'})`
                  : 'No confirmed path (safety not guaranteed)'}
              </span>
            </div>

            <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 text-slate-400 text-[11px] leading-relaxed">
              <span className="font-semibold text-slate-300">Provenance Notice:</span> Stored security
              data originates from OSV database ingestion and lockfile manifest resolution in FalkorDB.
            </div>
          </div>
        </div>
      </div>

      {/* US-401: Upgrade Candidates & Remediation Targets */}
      <FindingUpgradeCandidatesSection
        projectId={activeProject?.id ?? finding.project_id}
        findingId={finding.id}
      />

      {/* Dependency Reachability & Interactive Exposure Paths (US-204) */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2 text-sm font-bold text-white">
            <Route className="h-4 w-4 text-sky-400" aria-hidden="true" />
            <span>Dependency Chain &amp; Graph Reachability (US-204)</span>
          </div>
          <Link
            to="/exposure-paths"
            className="text-xs font-semibold text-sky-400 hover:text-sky-300 transition-colors"
          >
            All Project Paths &rarr;
          </Link>
        </div>

        <DependencyPathVisualizer
          projectId={activeProject?.id ?? finding.project_id}
          findingId={finding.id}
        />
      </div>

      {/* US-603: Agent Investigation Traces & Session Audit */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2 text-sm font-bold text-white">
            <Bot className="h-4 w-4 text-sky-400" aria-hidden="true" />
            <span>Agent Investigation Traces (US-603)</span>
            {findingRuns.length > 0 && (
              <span className="rounded-full bg-sky-500/15 border border-sky-500/30 px-2 py-0.5 text-[10px] font-mono font-bold text-sky-300">
                {findingRuns.length} recorded
              </span>
            )}
          </div>
          <Link
            to="/investigation"
            className="inline-flex items-center gap-1 text-xs font-semibold text-sky-400 hover:text-sky-300 transition-colors"
          >
            <span>Ask Agent New Question</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>

        {isLoadingRuns ? (
          <div className="flex items-center justify-center p-8 text-xs text-slate-400 gap-2">
            <Loader2 className="h-4 w-4 animate-spin text-sky-400" />
            <span>Checking for recorded agent investigation traces...</span>
          </div>
        ) : findingRuns.length === 0 ? (
          <div className="rounded-lg border border-slate-800/80 bg-[#0b121a] p-5 text-center text-xs text-slate-400 space-y-2">
            <Database className="h-6 w-6 text-slate-600 mx-auto" />
            <p className="font-medium text-slate-300">No agent investigation runs recorded for this finding yet.</p>
            <p className="text-[11px] text-slate-500 max-w-md mx-auto">
              When the AI security agent investigates exposure paths or remediation options referencing this finding, its full parameterized Cypher trace and decision rationale are saved here.
            </p>
            <div className="pt-2">
              <Link
                to={`/investigation`}
                className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500/15 border border-sky-500/30 px-3 py-1.5 text-xs font-semibold text-sky-300 hover:bg-sky-500/25 transition-colors"
              >
                <Bot className="h-3.5 w-3.5" />
                <span>Investigate with Agent</span>
              </Link>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-xs text-slate-400">
              The following AI agent investigation sessions analyzed or referenced this finding. Inspect the execution trace to verify parameterized Cypher queries, tool outputs, and reasoning steps.
            </p>
            <div className="divide-y divide-slate-800 rounded-lg border border-slate-800 bg-[#0b121a] overflow-hidden">
              {findingRuns.map((r) => (
                <div
                  key={r.id}
                  className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-800/20 transition-colors"
                >
                  <div className="space-y-1 min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-sky-400 font-semibold">{r.id.substring(0, 16)}...</span>
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-800 text-slate-300">
                        {r.status}
                      </span>
                      <span className="text-[11px] text-slate-500 font-mono">
                        {r.tool_call_count} step{r.tool_call_count === 1 ? '' : 's'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-200 truncate font-medium" title={r.prompt}>
                      "{r.prompt}"
                    </p>
                    <div className="text-[10px] text-slate-500 font-mono">
                      {formatRetrievedDate(r.started_at)}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => {
                        setSelectedTraceRunId(r.id)
                        setIsTraceDrawerOpen(true)
                      }}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 hover:text-white transition-colors"
                    >
                      <Database className="h-3.5 w-3.5 text-sky-400" />
                      <span>View Trace</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => navigate(`/investigation?reopen=${encodeURIComponent(r.id)}`)}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/30 bg-sky-500/10 px-3 py-1.5 text-xs font-medium text-sky-300 hover:bg-sky-500/20 transition-colors"
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                      <span>Reopen in Chat</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Embedded Slide-over Trace Drawer (US-603) */}
      <TraceDrawer
        runId={selectedTraceRunId}
        isOpen={isTraceDrawerOpen}
        onClose={() => setIsTraceDrawerOpen(false)}
        onReopenRun={(run) => navigate(`/investigation?reopen=${encodeURIComponent(run.id)}`)}
      />
    </div>
  )
}
