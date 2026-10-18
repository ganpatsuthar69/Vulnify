import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  ArrowUpCircle,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Search,
  Filter,
  RefreshCw,
  Loader2,
  ExternalLink,
  ShieldAlert,
  Info,
  GitPullRequest,
  FlaskConical,
} from 'lucide-react'
import { Link } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import { getProjectUpgradeCandidates, ProjectApiError } from '@/features/projects/projectApi'
import type {
  ProjectUpgradeCandidatesResponse,
} from '@/features/projects/types'

export function UpgradeCandidatesPage() {
  const { activeProject } = useProjects()
  const [data, setData] = useState<ProjectUpgradeCandidatesResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [searchTerm, setSearchTerm] = useState('')
  const [fixFilter, setFixFilter] = useState<'all' | 'available' | 'none'>('all')
  const [jumpFilter, setJumpFilter] = useState<string>('all')

  const loadData = useCallback(async (projectId: string) => {
    setIsLoading(true)
    setError(null)
    try {
      const res = await getProjectUpgradeCandidates(projectId)
      setData(res)
    } catch (err) {
      if (err instanceof ProjectApiError) {
        setError(err.message)
      } else {
        setError('Failed to load project upgrade candidates.')
      }
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    if (activeProject) {
      void loadData(activeProject.id)
    } else {
      setData(null)
    }
  }, [activeProject, loadData])

  const items = data?.items ?? []

  const filteredItems = useMemo(() => {
    return items.filter((item) => {
      const matchesSearch =
        item.package_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.advisory_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.finding_id.toLowerCase().includes(searchTerm.toLowerCase())

      const matchesFix =
        fixFilter === 'all' ||
        (fixFilter === 'available' && item.has_fix) ||
        (fixFilter === 'none' && !item.has_fix)

      const matchesJump =
        jumpFilter === 'all' ||
        item.candidates.some((c) => c.semver_diff === jumpFilter)

      return matchesSearch && matchesFix && matchesJump
    })
  }, [items, searchTerm, fixFilter, jumpFilter])

  const totalFindingsWithFix = data?.findings_with_fix ?? 0
  const totalFindingsWithoutFix = data?.findings_without_fix ?? 0
  const totalMajorJumps = useMemo(() => {
    return items.filter((item) =>
      item.candidates.some((c) => c.semver_diff === 'major'),
    ).length
  }, [items])

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white">Upgrade Candidates</h1>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Suggested upgrade targets derived strictly from advisory fixed versions and server-evaluated SemVer differentials.
          </p>
        </div>

        <button
          type="button"
          onClick={() => activeProject && void loadData(activeProject.id)}
          disabled={isLoading || !activeProject}
          className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-700 hover:bg-slate-800 disabled:opacity-50 transition-colors"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* AC-2: Universal Safety Notice - NEVER claim safe to ship */}
      <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-4 text-xs text-sky-200">
        <div className="flex items-start gap-2.5">
          <Info className="h-4 w-4 text-sky-400 mt-0.5 shrink-0" aria-hidden="true" />
          <div className="space-y-1">
            <span className="font-semibold text-white">Remediation Policy &amp; Safety Guidance:</span>
            <p className="text-sky-200/90 leading-relaxed text-[11px]">
              {data?.safety_disclaimer ||
                'No upgrade is guaranteed safe to ship. Upstream fixed versions indicate that the security advisory reports the vulnerability as resolved in that release. Upgrades may introduce regressions, breaking changes, or undeclared side effects. Always run test suites and security validation before deploying to production.'}
            </p>
          </div>
        </div>
      </div>

      {/* Summary KPI Badges */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4 shadow-sm">
          <span className="text-xs font-medium text-slate-400">Fix Available</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">{totalFindingsWithFix}</span>
            <span className="text-xs text-emerald-400 font-semibold">Upgradeable</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4 shadow-sm">
          <span className="text-xs font-medium text-slate-400">Breaking Change Risk</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-amber-300">{totalMajorJumps}</span>
            <span className="text-xs text-amber-400/90 font-medium">Major SemVer Jumps</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4 shadow-sm">
          <span className="text-xs font-medium text-slate-400">No Upstream Fix</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-300">{totalFindingsWithoutFix}</span>
            <span className="text-xs text-slate-400 font-medium">Pending vendor fix</span>
          </div>
        </div>
      </div>

      {/* Filters & Search Bar */}
      <div className="flex flex-col sm:flex-row items-center gap-3">
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" aria-hidden="true" />
          <input
            type="text"
            aria-label="Search upgrade candidates"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by package name, advisory ID, or finding ID..."
            className="w-full rounded-lg border border-slate-800 bg-[#0f1822] py-2 pl-9 pr-3 text-xs text-slate-200 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="h-3.5 w-3.5 text-slate-400 shrink-0" aria-hidden="true" />
          <select
            aria-label="Filter by fix availability"
            value={fixFilter}
            onChange={(e) => setFixFilter(e.target.value as 'all' | 'available' | 'none')}
            className="rounded-lg border border-slate-800 bg-[#0f1822] px-3 py-2 text-xs text-slate-300 focus:border-sky-500 focus:outline-none"
          >
            <option value="all">All Fix Statuses</option>
            <option value="available">Candidate Available</option>
            <option value="none">No Fix Available</option>
          </select>

          <select
            aria-label="Filter by SemVer differential"
            value={jumpFilter}
            onChange={(e) => setJumpFilter(e.target.value)}
            className="rounded-lg border border-slate-800 bg-[#0f1822] px-3 py-2 text-xs text-slate-300 focus:border-sky-500 focus:outline-none"
          >
            <option value="all">All SemVer Differentials</option>
            <option value="major">Major (Breaking Risk)</option>
            <option value="minor">Minor Version</option>
            <option value="patch">Patch Only</option>
          </select>
        </div>
      </div>

      {/* Main Table / Candidates List */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] overflow-hidden shadow-xl">
        {isLoading ? (
          <div className="flex flex-col items-center justify-center p-12 text-slate-400">
            <Loader2 className="h-7 w-7 animate-spin text-sky-400 mb-3" />
            <span className="text-xs">Analyzing advisory remediation evidence and SemVer deltas...</span>
          </div>
        ) : error ? (
          <div className="p-8 text-center text-xs text-red-400">
            <AlertTriangle className="h-6 w-6 text-red-400 mx-auto mb-2" />
            <span>{error}</span>
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-400 space-y-2">
            <CheckCircle className="h-8 w-8 text-slate-600 mx-auto" />
            <div className="font-semibold text-slate-300">No upgrade candidates match the filter</div>
            <p className="text-slate-500 max-w-sm mx-auto">
              {!activeProject
                ? 'Select or create a project to review upgrade options.'
                : 'Adjust search filters or run advisory scanning from Import Data.'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {filteredItems.map((item) => {
              const recCandidate = item.candidates.find((c) => c.is_recommended) || item.candidates[0]

              return (
                <div key={item.finding_id} className="p-5 hover:bg-slate-800/25 transition-colors space-y-3">
                  <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                    {/* Package Info & Version Hop */}
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2.5">
                        <span className="font-mono text-sm font-bold text-white">{item.package_name}</span>
                        <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-medium text-slate-400 uppercase">
                          {item.ecosystem}
                        </span>
                        <span className="rounded bg-slate-800/80 border border-slate-700/60 px-2 py-0.5 text-[10px] font-medium text-slate-300">
                          Service: {item.service_name}
                        </span>
                        {item.path_depth !== null && (
                          <span className="text-[11px] text-slate-400 font-mono">
                            ({item.is_transitive ? `Transitive: ${item.path_depth} hops` : 'Direct dependency'})
                          </span>
                        )}
                      </div>

                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <span className="text-slate-400">Current:</span>
                        <code className="rounded bg-slate-800 px-2 py-0.5 font-mono text-slate-300">
                          {item.current_version}
                        </code>
                        <span className="text-slate-500">&rarr;</span>
                        <span className="text-slate-400">Target:</span>
                        {item.has_fix && recCandidate ? (
                          <code className="rounded bg-emerald-500/15 border border-emerald-500/30 px-2 py-0.5 font-mono font-semibold text-emerald-300">
                            {recCandidate.target_version}
                          </code>
                        ) : (
                          <span className="rounded bg-slate-800 border border-slate-700 px-2 py-0.5 text-[11px] font-medium text-slate-400">
                            No fix available
                          </span>
                        )}

                        {recCandidate && (
                          <span className="text-slate-500 text-[11px] font-mono">
                            ({recCandidate.semver_diff} jump)
                          </span>
                        )}
                      </div>
                    </div>

                    {/* AC-1: Classification Badges */}
                    <div className="flex flex-wrap items-center gap-2">
                      {item.has_fix ? (
                        item.candidates.map((cand) => (
                          <div
                            key={cand.target_version}
                            className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-medium border ${
                              cand.is_recommended
                                ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300 font-semibold'
                                : cand.semver_diff === 'major'
                                ? 'bg-amber-500/15 border-amber-500/40 text-amber-300'
                                : 'bg-slate-800 border-slate-700 text-slate-300'
                            }`}
                          >
                            {cand.is_recommended ? (
                              <CheckCircle className="h-3 w-3 text-emerald-400" />
                            ) : cand.semver_diff === 'major' ? (
                              <AlertTriangle className="h-3 w-3 text-amber-400" />
                            ) : (
                              <ArrowUpCircle className="h-3 w-3 text-sky-400" />
                            )}
                            <span>v{cand.target_version}</span>
                            <span className="text-[10px] opacity-75 capitalize">({cand.label})</span>
                          </div>
                        ))
                      ) : (
                        <div className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1 text-xs font-medium text-slate-400">
                          <XCircle className="h-3.5 w-3.5 text-slate-500" />
                          <span>No Vendor Fix Published</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* AC-2: Compatibility Caveats for primary candidate */}
                  {recCandidate && recCandidate.caveats && recCandidate.caveats.length > 0 && (
                    <div className="rounded-lg border border-slate-800/80 bg-[#0b121a] p-3 text-xs text-slate-300 space-y-1">
                      <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 block">
                        Compatibility Caveats:
                      </span>
                      <ul className="space-y-0.5 text-[11px] text-slate-300">
                        {recCandidate.caveats.map((caveat, cIdx) => (
                          <li key={cIdx} className="flex items-start gap-1.5">
                            <span className="mt-1 h-1 w-1 rounded-full bg-slate-500 shrink-0" />
                            <span className="leading-relaxed">{caveat}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* AC-3: No fix message */}
                  {!item.has_fix && (
                    <div className="rounded-lg border border-slate-800/80 bg-[#0b121a] p-3 text-xs text-slate-400 space-y-1">
                      <span className="font-semibold text-slate-300 block">Defensive Status:</span>
                      <p className="text-[11px] leading-relaxed">
                        {item.no_fix_message || 'No fix is published in the advisory. Automated upgrade is not possible.'}
                      </p>
                    </div>
                  )}

                  {/* Action Links */}
                  <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/50 text-xs">
                    <Link
                      to={`/findings/${item.finding_id}`}
                      className="group inline-flex items-center gap-1.5 text-sky-400 hover:text-sky-300 font-mono transition-colors"
                    >
                      <ShieldAlert className="h-3.5 w-3.5 text-red-400" />
                      <span>{item.advisory_id}</span>
                      <span className="text-slate-500">({item.finding_id})</span>
                      <ExternalLink className="h-3 w-3 text-slate-600 group-hover:text-sky-400" />
                    </Link>

                    {item.has_fix && recCandidate && (
                      <div className="flex items-center gap-2">
                        <Link
                          to={`/simulation?finding=${encodeURIComponent(item.finding_id)}&target=${encodeURIComponent(recCandidate.target_version)}`}
                          className="inline-flex items-center gap-1 rounded bg-sky-950/40 border border-sky-500/30 hover:bg-sky-900/60 px-2.5 py-1 text-sky-300 hover:text-white transition-colors"
                        >
                          <FlaskConical className="h-3 w-3 text-sky-400" />
                          <span>Simulate Fix</span>
                        </Link>

                        <Link
                          to={`/github-issues?finding=${encodeURIComponent(item.finding_id)}&target=${encodeURIComponent(recCandidate.target_version)}`}
                          className="inline-flex items-center gap-1 rounded bg-slate-800 hover:bg-slate-700 px-2.5 py-1 text-slate-300 hover:text-white transition-colors"
                        >
                          <GitPullRequest className="h-3 w-3 text-sky-400" />
                          <span>Preview Remediation Plan &rarr;</span>
                        </Link>
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
