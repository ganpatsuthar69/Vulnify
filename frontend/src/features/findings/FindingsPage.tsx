import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  Search,
  Filter,
  Loader2,
  RefreshCw,
  AlertCircle,
  ArrowRight,
  ShieldCheck,
} from 'lucide-react'
import { Link, useSearchParams } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import { getProjectVulnerabilities } from '@/features/projects/projectApi'
import type { VulnerabilityFinding } from '@/features/projects/types'

export function FindingsPage() {
  const { activeProject } = useProjects()
  const [searchParams, setSearchParams] = useSearchParams()

  const [findings, setFindings] = useState<VulnerabilityFinding[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // URL-persisted search and filter states
  const searchTerm = searchParams.get('q') || ''
  const severityFilter = searchParams.get('severity') || 'ALL'

  const loadFindings = useCallback(async (projectId: string) => {
    setIsLoading(true)
    setError(null)
    try {
      const data = await getProjectVulnerabilities(projectId)
      setFindings(data)
    } catch {
      setError('Failed to load project vulnerability findings.')
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    if (activeProject) {
      void loadFindings(activeProject.id)
    } else {
      setFindings([])
    }
  }, [activeProject, loadFindings])

  const handleSearchChange = (term: string) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      if (term) next.set('q', term)
      else next.delete('q')
      return next
    })
  }

  const handleSeverityChange = (sev: string) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      if (sev && sev !== 'ALL') next.set('severity', sev)
      else next.delete('severity')
      return next
    })
  }

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const matchesSearch =
        f.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.package_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.summary.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.aliases.some((a) => a.toLowerCase().includes(searchTerm.toLowerCase()))

      const matchesSeverity =
        severityFilter === 'ALL' || f.severity.toUpperCase() === severityFilter.toUpperCase()

      return matchesSearch && matchesSeverity
    })
  }, [findings, searchTerm, severityFilter])

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return 'border-red-500/40 bg-red-500/15 text-red-300'
      case 'HIGH':
        return 'border-orange-500/40 bg-orange-500/15 text-orange-300'
      case 'MODERATE':
      case 'MEDIUM':
        return 'border-amber-500/40 bg-amber-500/15 text-amber-300'
      case 'LOW':
        return 'border-blue-500/40 bg-blue-500/15 text-blue-300'
      default:
        return 'border-slate-600 bg-slate-800 text-slate-300'
    }
  }

  if (!activeProject) {
    return (
      <div className="rounded-xl border border-dashed border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
        <AlertCircle className="mx-auto h-8 w-8 text-amber-400" aria-hidden="true" />
        <h2 className="mt-3 text-sm font-bold text-white">No Active Project Selected</h2>
        <p className="mt-1 text-slate-400">
          Please select or create a project in the top navigation bar to view findings.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-white">Vulnerability Findings</h1>
            <span className="rounded-full bg-red-500/20 border border-red-500/30 px-2.5 py-0.5 text-xs font-semibold text-red-300">
              {findings.length} confirmed
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Advisories confirmed to affect installed versions via ecosystem version comparison rules for{' '}
            <span className="font-semibold text-slate-200">{activeProject.name}</span>.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Link
            to="/import"
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-sky-400 transition-colors"
          >
            <span>Run Matching</span>
          </Link>
          <button
            type="button"
            onClick={() => void loadFindings(activeProject.id)}
            disabled={isLoading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-700 hover:text-white transition-colors disabled:opacity-50"
            title="Refresh findings"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin text-sky-400' : ''}`}
              aria-hidden="true"
            />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div
          role="alert"
          className="flex items-center justify-between rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-200"
        >
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-rose-400 shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </div>
          <button
            type="button"
            onClick={() => void loadFindings(activeProject.id)}
            className="rounded bg-rose-500/20 px-2.5 py-1 font-semibold text-rose-200 hover:bg-rose-500/30"
          >
            Retry
          </button>
        </div>
      )}

      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 rounded-xl border border-slate-800 bg-[#0f1822] p-4">
        <div className="flex flex-1 flex-col sm:flex-row items-center gap-3 w-full">
          <div className="relative w-full sm:w-80">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" aria-hidden="true" />
            <input
              type="search"
              value={searchTerm}
              onChange={(e) => handleSearchChange(e.target.value)}
              placeholder="Search advisory, CVE, package..."
              className="w-full rounded-lg border border-slate-700 bg-[#0b121a] py-2 pl-9 pr-3 text-xs text-slate-200 placeholder-slate-500 transition-colors focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <Filter className="h-3.5 w-3.5 text-slate-400 shrink-0" aria-hidden="true" />
            <select
              value={severityFilter}
              onChange={(e) => handleSeverityChange(e.target.value)}
              className="rounded-lg border border-slate-700 bg-[#0b121a] px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium / Moderate</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>

        <div className="text-xs text-slate-400">
          Showing <span className="font-semibold text-white">{filteredFindings.length}</span> of{' '}
          {findings.length} findings
        </div>
      </div>

      {/* Findings Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] shadow-xl overflow-hidden">
        {isLoading ? (
          <div className="flex flex-col items-center justify-center p-12 text-slate-400">
            <Loader2 className="h-8 w-8 animate-spin text-sky-400" aria-hidden="true" />
            <span className="mt-3 text-xs font-medium text-slate-300">
              Querying verified vulnerability findings...
            </span>
          </div>
        ) : findings.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-400">
            <ShieldCheck className="mx-auto h-8 w-8 text-emerald-400" aria-hidden="true" />
            <h3 className="mt-3 font-semibold text-white">No confirmed vulnerabilities</h3>
            <p className="mt-1 text-slate-500">
              Either no matching advisories were found, or all installed versions are safely outside
              affected ranges.
            </p>
            <Link
              to="/import"
              className="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-2 text-xs font-semibold text-white hover:bg-sky-400 transition-colors"
            >
              <span>Review Ingestion Stages</span>
            </Link>
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-400">
            No findings match your active search or filter criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/40 text-slate-400">
                  <th className="py-3 px-4 font-semibold">Severity</th>
                  <th className="py-3 px-4 font-semibold">Advisory</th>
                  <th className="py-3 px-4 font-semibold">Package &amp; Version</th>
                  <th className="py-3 px-4 font-semibold">Match Reason</th>
                  <th className="py-3 px-4 font-semibold">Fixed In</th>
                  <th className="py-3 px-4 font-semibold text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredFindings.map((finding) => (
                  <tr
                    key={`${finding.id}-${finding.package_version_id}`}
                    className="hover:bg-slate-900/40 transition-colors"
                  >
                    <td className="py-3 px-4">
                      <span
                        className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border ${getSeverityBadgeClass(
                          finding.severity,
                        )}`}
                      >
                        {finding.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="font-mono font-semibold text-white">{finding.id}</div>
                      {finding.aliases.length > 0 && (
                        <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                          {finding.aliases.join(', ')}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <div className="font-semibold text-white">{finding.package_name}</div>
                      <div className="font-mono text-slate-400 text-[11px]">
                        @{finding.package_version}
                      </div>
                    </td>
                    <td className="py-3 px-4 max-w-xs truncate text-slate-300" title={finding.match_reason}>
                      {finding.match_reason}
                    </td>
                    <td className="py-3 px-4 font-mono font-semibold text-emerald-400">
                      {finding.fixed_version ? `>= ${finding.fixed_version}` : 'None'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <Link
                        to={`/findings/${encodeURIComponent(finding.id)}`}
                        className="inline-flex items-center gap-1 rounded bg-slate-800 px-2.5 py-1 text-slate-200 hover:bg-slate-700 hover:text-white font-semibold transition-colors"
                      >
                        <span>Evidence</span>
                        <ArrowRight className="h-3 w-3" aria-hidden="true" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
