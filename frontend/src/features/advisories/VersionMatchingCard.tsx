import { useState, useEffect, useCallback } from 'react'
import {
  ShieldAlert,
  ShieldCheck,
  HelpCircle,
  Loader2,
  RefreshCw,
  AlertCircle,
  ExternalLink,
  Cpu,
} from 'lucide-react'
import {
  matchProjectVulnerabilities,
  getProjectVulnerabilities,
  ProjectApiError,
} from '../projects/projectApi'
import type {
  Project,
  ProjectMatchResponse,
  VulnerabilityFinding,
} from '../projects/types'

interface VersionMatchingCardProps {
  project: Project
}

export function VersionMatchingCard({ project }: VersionMatchingCardProps) {
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([])
  const [matchSummary, setMatchSummary] = useState<ProjectMatchResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [isMatching, setIsMatching] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadFindings = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const data = await getProjectVulnerabilities(project.id)
      setFindings(data)
    } catch (err) {
      if (err instanceof ProjectApiError) {
        setError(err.message)
      } else {
        setError('Failed to load vulnerability findings.')
      }
    } finally {
      setIsLoading(false)
    }
  }, [project.id])

  useEffect(() => {
    void loadFindings()
    setMatchSummary(null)
  }, [loadFindings])

  const handleRunMatching = async () => {
    setIsMatching(true)
    setError(null)
    try {
      const result = await matchProjectVulnerabilities(project.id)
      setMatchSummary(result)
      await loadFindings()
    } catch (err) {
      if (err instanceof ProjectApiError) {
        setError(err.message)
      } else {
        setError('Failed to run version matching.')
      }
    } finally {
      setIsMatching(false)
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'affected':
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-red-500/40 bg-red-500/15 px-2.5 py-0.5 text-xs font-semibold text-red-300">
            <ShieldAlert className="h-3 w-3" />
            Affected
          </span>
        )
      case 'not_affected':
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-0.5 text-xs font-semibold text-emerald-300">
            <ShieldCheck className="h-3 w-3" />
            Not Affected
          </span>
        )
      default:
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2.5 py-0.5 text-xs font-semibold text-amber-300">
            <HelpCircle className="h-3 w-3" />
            Unknown
          </span>
        )
    }
  }

  const getSeverityBadge = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return 'border-red-500/30 bg-red-500/10 text-red-300'
      case 'HIGH':
        return 'border-orange-500/30 bg-orange-500/10 text-orange-300'
      case 'MODERATE':
      case 'MEDIUM':
        return 'border-amber-500/30 bg-amber-500/10 text-amber-300'
      case 'LOW':
        return 'border-blue-500/30 bg-blue-500/10 text-blue-300'
      default:
        return 'border-slate-600 bg-slate-800 text-slate-300'
    }
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-500/10 text-indigo-400 ring-1 ring-indigo-500/20">
            <Cpu className="h-5 w-5" aria-hidden="true" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              Ecosystem-Aware Version Matching
              {findings.length > 0 && (
                <span className="rounded-full bg-red-500/20 border border-red-500/30 px-2 py-0.5 text-xs font-semibold text-red-300">
                  {findings.length} exposure findings
                </span>
              )}
            </h3>
            <p className="text-xs text-slate-400">
              Evaluates installed package versions against OSV advisories using ecosystem semantics (npm SemVer / PyPI PEP 440).
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => void handleRunMatching()}
            disabled={isMatching || isLoading}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-indigo-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400 disabled:opacity-50"
          >
            {isMatching ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                <span>Evaluating...</span>
              </>
            ) : (
              <>
                <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Evaluate Version Matching</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div
          role="alert"
          className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300"
        >
          <AlertCircle className="h-4 w-4 flex-shrink-0 text-red-400" aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}

      {/* Evaluation Execution Summary */}
      {matchSummary && (
        <div className="rounded-lg border border-indigo-500/30 bg-indigo-500/5 p-4 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-wider text-indigo-300">
              Version Matching Execution Results
            </span>
            <span className="text-[11px] text-slate-400">
              Completed in {matchSummary.duration_ms} ms
            </span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
            <div className="rounded border border-slate-800 bg-[#0b121a] p-2.5">
              <div className="text-[11px] text-slate-400">Evaluated</div>
              <div className="text-base font-bold text-white">{matchSummary.total_evaluated}</div>
            </div>
            <div className="rounded border border-red-500/30 bg-red-500/10 p-2.5">
              <div className="text-[11px] text-red-300">Affected</div>
              <div className="text-base font-bold text-red-200">{matchSummary.affected_count}</div>
            </div>
            <div className="rounded border border-emerald-500/30 bg-emerald-500/10 p-2.5">
              <div className="text-[11px] text-emerald-300">Not Affected</div>
              <div className="text-base font-bold text-emerald-200">{matchSummary.not_affected_count}</div>
            </div>
            <div className="rounded border border-amber-500/30 bg-amber-500/10 p-2.5">
              <div className="text-[11px] text-amber-300">Unknown</div>
              <div className="text-base font-bold text-amber-200">{matchSummary.unknown_count}</div>
            </div>
          </div>
        </div>
      )}

      {/* Findings List */}
      <div className="space-y-3">
        {isLoading ? (
          <div className="flex items-center justify-center p-8 text-slate-400 text-xs">
            <Loader2 className="h-5 w-5 animate-spin mr-2 text-indigo-400" />
            Loading vulnerability findings...
          </div>
        ) : findings.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-800 p-8 text-center">
            <ShieldCheck className="h-10 w-10 text-slate-500 mb-2" />
            <p className="text-xs font-medium text-slate-300">No confirmed vulnerability exposures</p>
            <p className="text-[11px] text-slate-500 max-w-sm mt-1">
              Either no advisories target your packages, or all evaluated package versions fall outside affected ranges. Click &quot;Evaluate Version Matching&quot; above to run or refresh.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {findings.map((f) => (
              <div
                key={`${f.id}-${f.package_version_id}`}
                className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 transition-colors hover:border-slate-700 space-y-3"
              >
                {/* Header row: Package, Version, Advisory ID, Status */}
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-semibold text-white">
                      {f.package_name}
                    </span>
                    <span className="font-mono text-xs text-indigo-400 bg-indigo-500/10 border border-indigo-500/20 px-2 py-0.5 rounded">
                      v{f.package_version}
                    </span>
                    <span className="text-[10px] uppercase font-bold text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
                      {f.ecosystem}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span
                      className={`inline-flex items-center rounded px-2 py-0.5 text-[11px] font-bold uppercase ${getSeverityBadge(
                        f.severity
                      )}`}
                    >
                      {f.severity}
                    </span>
                    {getStatusBadge(f.match_status)}
                  </div>
                </div>

                {/* Advisory Summary & Link */}
                <div className="text-xs text-slate-300">
                  <div className="font-medium flex items-center gap-2">
                    <span>{f.id}</span>
                    {f.aliases && f.aliases.length > 0 && (
                      <span className="text-[11px] text-slate-400">
                        ({f.aliases.join(', ')})
                      </span>
                    )}
                    {f.source_url && (
                      <a
                        href={f.source_url}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center text-indigo-400 hover:text-indigo-300 ml-1"
                        aria-label={`Open source advisory ${f.id}`}
                      >
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    )}
                  </div>
                  <p className="text-slate-400 text-[11px] mt-0.5 line-clamp-2">
                    {f.summary}
                  </p>
                </div>

                {/* Match Reason and Boundaries */}
                <div className="rounded border border-slate-800/80 bg-[#080d13] p-3 text-xs space-y-1.5">
                  <div className="text-[11px] text-slate-400 font-semibold uppercase tracking-wider">
                    Evaluation Reason
                  </div>
                  <p className="text-slate-200 text-xs">
                    {f.match_reason}
                  </p>
                  <div className="flex flex-wrap items-center gap-4 pt-1 text-[11px] text-slate-400">
                    {f.matched_range && (
                      <div className="flex items-center gap-1">
                        <span className="text-slate-500">Affected Range:</span>
                        <span className="font-mono font-medium text-slate-300">{f.matched_range}</span>
                      </div>
                    )}
                    {f.fixed_version && (
                      <div className="flex items-center gap-1">
                        <span className="text-slate-500">Fixed In:</span>
                        <span className="font-mono font-semibold text-emerald-400">{f.fixed_version}</span>
                      </div>
                    )}
                    {f.comparator && (
                      <div className="flex items-center gap-1">
                        <span className="text-slate-500">Comparator:</span>
                        <span className="font-mono text-slate-300">{f.comparator}</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
