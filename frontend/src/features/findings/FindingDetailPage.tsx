import { useState, useEffect } from 'react'
import {
  ArrowLeft,
  ShieldAlert,
  ExternalLink,
  Loader2,
  CheckCircle2,
  Route,
  GitPullRequest,
  AlertTriangle,
  RefreshCw,
  Clock,
} from 'lucide-react'
import { Link, useParams } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import { getProjectFindingDetail, ProjectApiError } from '@/features/projects/projectApi'
import type { FindingDetail } from '@/features/projects/types'
import { DependencyPathVisualizer } from '@/features/graph/DependencyPathVisualizer'

export function FindingDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { activeProject } = useProjects()

  const [finding, setFinding] = useState<FindingDetail | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isNotFound, setIsNotFound] = useState(false)
  const [reloadTrigger, setReloadTrigger] = useState(0)

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
            </span>

            {/* Triage Status */}
            <span className="rounded border border-slate-700 bg-slate-800/80 px-2 py-0.5 text-xs font-medium text-slate-300">
              Status: <strong className="text-white capitalize">{finding.status}</strong>
            </span>
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
                  : 'No confirmed path'}
              </span>
            </div>

            <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 text-slate-400 text-[11px] leading-relaxed">
              <span className="font-semibold text-slate-300">Provenance Notice:</span> Stored security
              data originates from OSV database ingestion and lockfile manifest resolution in FalkorDB.
            </div>
          </div>
        </div>
      </div>

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
    </div>
  )
}
