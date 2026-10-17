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
} from 'lucide-react'
import { Link } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import { getProjectVulnerabilities } from '@/features/projects/projectApi'
import type { VulnerabilityFinding } from '@/features/projects/types'

interface CandidateGroup {
  packageName: string
  currentVersion: string
  ecosystem: string
  fixedVersion: string | null
  jumpType: 'major' | 'minor' | 'patch' | 'none'
  findings: VulnerabilityFinding[]
}

function parseSemVer(ver: string): { major: number; minor: number; patch: number } | null {
  const clean = ver.replace(/^[v^~>=<]+/, '').split('-')[0]
  if (!clean) return null
  const parts = clean.split('.').map((p) => parseInt(p, 10))
  if (parts.length > 0 && !isNaN(parts[0]!)) {
    return {
      major: parts[0]!,
      minor: parts[1] ?? 0,
      patch: parts[2] ?? 0,
    }
  }
  return null
}

function classifySemVerJump(current: string, fixed: string | null): 'major' | 'minor' | 'patch' | 'none' {
  if (!fixed) return 'none'
  const c = parseSemVer(current)
  const f = parseSemVer(fixed)
  if (!c || !f) return 'minor'
  if (f.major > c.major) return 'major'
  if (f.minor > c.minor) return 'minor'
  return 'patch'
}

export function UpgradeCandidatesPage() {
  const { activeProject } = useProjects()
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [searchTerm, setSearchTerm] = useState('')
  const [fixFilter, setFixFilter] = useState<'all' | 'available' | 'none'>('all')
  const [jumpFilter, setJumpFilter] = useState<string>('all')

  const loadData = useCallback(async (projectId: string) => {
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
      void loadData(activeProject.id)
    } else {
      setFindings([])
    }
  }, [activeProject, loadData])

  // Group findings by package + current_version
  const candidateGroups = useMemo<CandidateGroup[]>(() => {
    const map = new Map<string, CandidateGroup>()

    for (const f of findings) {
      const key = `${f.package_name}__${f.package_version}`
      if (!map.has(key)) {
        map.set(key, {
          packageName: f.package_name,
          currentVersion: f.package_version,
          ecosystem: f.ecosystem,
          fixedVersion: f.fixed_version || null,
          jumpType: classifySemVerJump(f.package_version, f.fixed_version || null),
          findings: [f],
        })
      } else {
        const group = map.get(key)!
        group.findings.push(f)
        // If current group has no fixed version but this finding does, update candidate
        if (!group.fixedVersion && f.fixed_version) {
          group.fixedVersion = f.fixed_version
          group.jumpType = classifySemVerJump(group.currentVersion, f.fixed_version)
        }
      }
    }

    return Array.from(map.values())
  }, [findings])

  const filteredGroups = useMemo(() => {
    return candidateGroups.filter((g) => {
      const matchesSearch =
        g.packageName.toLowerCase().includes(searchTerm.toLowerCase()) ||
        g.findings.some((f) => f.id.toLowerCase().includes(searchTerm.toLowerCase()))

      const matchesFix =
        fixFilter === 'all' ||
        (fixFilter === 'available' && g.fixedVersion !== null) ||
        (fixFilter === 'none' && g.fixedVersion === null)

      const matchesJump = jumpFilter === 'all' || g.jumpType === jumpFilter

      return matchesSearch && matchesFix && matchesJump
    })
  }, [candidateGroups, searchTerm, fixFilter, jumpFilter])

  const totalCandidates = candidateGroups.filter((g) => g.fixedVersion !== null).length
  const totalUnfixed = candidateGroups.filter((g) => g.fixedVersion === null).length
  const majorJumps = candidateGroups.filter((g) => g.jumpType === 'major').length

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white">Upgrade Candidates</h1>
            <span className="rounded-full bg-sky-500/15 border border-sky-500/30 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-sky-300">
              US-501
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Suggested upgrade targets derived from advisory remediation metadata and SemVer jump analysis.
          </p>
        </div>

        <button
          type="button"
          onClick={() => activeProject && void loadData(activeProject.id)}
          disabled={isLoading || !activeProject}
          className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-700 hover:bg-slate-800 disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Honesty & Caution Notice */}
      <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-4 text-xs text-sky-200">
        <div className="flex items-start gap-2.5">
          <Info className="h-4 w-4 text-sky-400 mt-0.5 shrink-0" aria-hidden="true" />
          <div className="space-y-1">
            <span className="font-semibold text-white">Remediation Policy & Compatibility Guidance:</span>
            <p className="text-sky-200/90 leading-relaxed">
              Upgrade candidates are gathered directly from OSV advisory remediation fields. Vulnify labels
              breaking-change risk based on SemVer jumps, but never guarantees an upgrade is safe to ship
              without project-level integration testing and regression validation.
            </p>
          </div>
        </div>
      </div>

      {/* Summary KPI Badges */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4">
          <span className="text-xs font-medium text-slate-400">Fix Available</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">{totalCandidates}</span>
            <span className="text-xs text-emerald-400 font-semibold">Upgradeable</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4">
          <span className="text-xs font-medium text-slate-400">Breaking Change Risk</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-amber-300">{majorJumps}</span>
            <span className="text-xs text-amber-400/90 font-medium">Major SemVer Jumps</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4">
          <span className="text-xs font-medium text-slate-400">No Upstream Fix</span>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-300">{totalUnfixed}</span>
            <span className="text-xs text-slate-400 font-medium">Pending vendor fix</span>
          </div>
        </div>
      </div>

      {/* Filters & Search Bar */}
      <div className="flex flex-col sm:flex-row items-center gap-3">
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by package name or advisory ID..."
            className="w-full rounded-lg border border-slate-800 bg-[#0f1822] py-2 pl-9 pr-3 text-xs text-slate-200 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="h-3.5 w-3.5 text-slate-400 shrink-0" />
          <select
            value={fixFilter}
            onChange={(e) => setFixFilter(e.target.value as 'all' | 'available' | 'none')}
            className="rounded-lg border border-slate-800 bg-[#0f1822] px-3 py-2 text-xs text-slate-300 focus:border-sky-500 focus:outline-none"
          >
            <option value="all">All Fix Statuses</option>
            <option value="available">Candidate Available</option>
            <option value="none">No Fix Available</option>
          </select>

          <select
            value={jumpFilter}
            onChange={(e) => setJumpFilter(e.target.value)}
            className="rounded-lg border border-slate-800 bg-[#0f1822] px-3 py-2 text-xs text-slate-300 focus:border-sky-500 focus:outline-none"
          >
            <option value="all">All SemVer Jumps</option>
            <option value="major">Major (Breaking Risk)</option>
            <option value="minor">Minor (Low Risk)</option>
            <option value="patch">Patch (Minimal)</option>
          </select>
        </div>
      </div>

      {/* Main Table / Groups List */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] overflow-hidden shadow-xl">
        {isLoading ? (
          <div className="flex flex-col items-center justify-center p-12 text-slate-400">
            <Loader2 className="h-7 w-7 animate-spin text-sky-400 mb-3" />
            <span className="text-xs">Analyzing remediation candidates and SemVer deltas...</span>
          </div>
        ) : error ? (
          <div className="p-8 text-center text-xs text-red-400">
            <AlertTriangle className="h-6 w-6 text-red-400 mx-auto mb-2" />
            <span>{error}</span>
          </div>
        ) : filteredGroups.length === 0 ? (
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
            {filteredGroups.map((group) => {
              const isAvailable = group.fixedVersion !== null

              return (
                <div key={`${group.packageName}@${group.currentVersion}`} className="p-5 hover:bg-slate-800/30 transition-colors">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    {/* Package Info & Version Hop */}
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-2.5">
                        <span className="font-mono text-sm font-bold text-white">{group.packageName}</span>
                        <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-medium text-slate-400">
                          {group.ecosystem}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 text-xs">
                        <span className="text-slate-400">Current:</span>
                        <code className="rounded bg-slate-800 px-2 py-0.5 font-mono text-slate-300">
                          {group.currentVersion}
                        </code>
                        <span className="text-slate-500">&rarr;</span>
                        <span className="text-slate-400">Target:</span>
                        {isAvailable ? (
                          <code className="rounded bg-emerald-500/15 border border-emerald-500/30 px-2 py-0.5 font-mono font-semibold text-emerald-300">
                            {group.fixedVersion}
                          </code>
                        ) : (
                          <span className="rounded bg-slate-800 border border-slate-700 px-2 py-0.5 text-[11px] font-medium text-slate-400">
                            No fix available
                          </span>
                        )}
                      </div>
                    </div>

                    {/* SemVer Jump Badge */}
                    <div className="flex items-center gap-3">
                      {group.jumpType === 'major' && (
                        <div className="flex items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/15 px-3 py-1 text-xs font-semibold text-amber-300">
                          <AlertTriangle className="h-3.5 w-3.5" />
                          <span>Major Jump (Breaking Risk)</span>
                        </div>
                      )}
                      {group.jumpType === 'minor' && (
                        <div className="flex items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/15 px-3 py-1 text-xs font-medium text-sky-300">
                          <ArrowUpCircle className="h-3.5 w-3.5" />
                          <span>Minor Jump</span>
                        </div>
                      )}
                      {group.jumpType === 'patch' && (
                        <div className="flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/15 px-3 py-1 text-xs font-medium text-emerald-300">
                          <CheckCircle className="h-3.5 w-3.5" />
                          <span>Patch Only</span>
                        </div>
                      )}
                      {group.jumpType === 'none' && (
                        <div className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1 text-xs font-medium text-slate-400">
                          <XCircle className="h-3.5 w-3.5" />
                          <span>Upstream Fix Pending</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Resolved Findings List */}
                  <div className="mt-4 pt-3 border-t border-slate-800/60">
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                      Resolved Findings ({group.findings.length})
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {group.findings.map((f) => (
                        <Link
                          key={f.id}
                          to={`/findings/${f.id}`}
                          className="group inline-flex items-center gap-1.5 rounded-md border border-slate-800 bg-[#0b121a] px-2.5 py-1 text-xs text-slate-300 hover:border-sky-500/50 hover:text-white transition-colors"
                        >
                          <ShieldAlert className="h-3 w-3 text-red-400 group-hover:text-red-300" />
                          <span className="font-mono">{f.id}</span>
                          <span className="text-[10px] text-slate-500 group-hover:text-slate-400">
                            ({f.severity})
                          </span>
                          <ExternalLink className="h-3 w-3 text-slate-600 group-hover:text-sky-400" />
                        </Link>
                      ))}
                    </div>
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
