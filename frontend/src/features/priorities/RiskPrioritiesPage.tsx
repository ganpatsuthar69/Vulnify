import { useState, useEffect, useMemo } from 'react'
import {
  ArrowRight,
  Loader2,
  Info,
  ShieldAlert,
} from 'lucide-react'
import { Link } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import { getProjectFindings } from '@/features/projects/projectApi'
import type { FindingItem } from '@/features/projects/types'

export function RiskPrioritiesPage() {
  const { activeProject } = useProjects()

  const [findings, setFindings] = useState<FindingItem[]>([])
  const [selectedBand, setSelectedBand] = useState<string>('ALL')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function loadData() {
      if (!activeProject) return
      setIsLoading(true)
      setError(null)
      try {
        const data = await getProjectFindings(activeProject.id, {
          page: 1,
          page_size: 100,
          sort_by: 'priority',
        })
        setFindings(data.items || [])
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Failed to retrieve ranked vulnerability findings.'
        setError(msg)
        setFindings([])
      } finally {
        setIsLoading(false)
      }
    }
    void loadData()
  }, [activeProject])

  const filteredRanked = useMemo(() => {
    if (selectedBand === 'ALL') return findings
    return findings.filter((f) => f.priority.toLowerCase() === selectedBand.toLowerCase())
  }, [findings, selectedBand])

  const bandCounts = useMemo(() => {
    return {
      Highest: findings.filter((f) => f.priority.toLowerCase() === 'highest').length,
      High: findings.filter((f) => f.priority.toLowerCase() === 'high').length,
      Medium: findings.filter((f) => f.priority.toLowerCase() === 'medium').length,
      Low: findings.filter((f) => f.priority.toLowerCase() === 'low').length,
    }
  }, [findings])

  if (!activeProject) {
    return (
      <div className="rounded-xl border border-dashed border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
        <h2 className="text-sm font-bold text-white">No Active Project Selected</h2>
        <p className="mt-1">Please select an active project to view risk prioritization.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-white">Risk Priorities &amp; Ranking</h1>
            <span className="rounded-full bg-sky-500/20 border border-sky-500/30 px-2.5 py-0.5 text-xs font-semibold text-sky-300">
              US-301 &bull; Backend Deterministic Scoring
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Findings ranked into deterministic priority bands with transparent reasons for{' '}
            <span className="font-semibold text-slate-200">{activeProject.name}</span>. Missing signals
            are treated as unknown, not zero risk.
          </p>
        </div>
      </div>

      {/* Priority Band Counters */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <button
          type="button"
          onClick={() => setSelectedBand(selectedBand === 'Highest' ? 'ALL' : 'Highest')}
          className={`rounded-xl border p-4 text-left transition-all ${
            selectedBand === 'Highest'
              ? 'border-red-500 bg-red-500/20 ring-1 ring-red-500'
              : 'border-slate-800 bg-[#0f1822] hover:border-slate-700'
          }`}
        >
          <div className="text-[11px] font-bold uppercase tracking-wider text-red-400">
            Highest Priority
          </div>
          <div className="mt-2 text-2xl font-bold text-white">{bandCounts.Highest}</div>
          <div className="mt-1 text-[11px] text-slate-400">Critical &bull; Reachable</div>
        </button>

        <button
          type="button"
          onClick={() => setSelectedBand(selectedBand === 'High' ? 'ALL' : 'High')}
          className={`rounded-xl border p-4 text-left transition-all ${
            selectedBand === 'High'
              ? 'border-orange-500 bg-orange-500/20 ring-1 ring-orange-500'
              : 'border-slate-800 bg-[#0f1822] hover:border-slate-700'
          }`}
        >
          <div className="text-[11px] font-bold uppercase tracking-wider text-orange-400">
            High Priority
          </div>
          <div className="mt-2 text-2xl font-bold text-white">{bandCounts.High}</div>
          <div className="mt-1 text-[11px] text-slate-400">High Severity &bull; Reachable</div>
        </button>

        <button
          type="button"
          onClick={() => setSelectedBand(selectedBand === 'Medium' ? 'ALL' : 'Medium')}
          className={`rounded-xl border p-4 text-left transition-all ${
            selectedBand === 'Medium'
              ? 'border-amber-500 bg-amber-500/20 ring-1 ring-amber-500'
              : 'border-slate-800 bg-[#0f1822] hover:border-slate-700'
          }`}
        >
          <div className="text-[11px] font-bold uppercase tracking-wider text-amber-400">
            Medium Priority
          </div>
          <div className="mt-2 text-2xl font-bold text-white">{bandCounts.Medium}</div>
          <div className="mt-1 text-[11px] text-slate-400">Moderate &bull; Unconfirmed</div>
        </button>

        <button
          type="button"
          onClick={() => setSelectedBand(selectedBand === 'Low' ? 'ALL' : 'Low')}
          className={`rounded-xl border p-4 text-left transition-all ${
            selectedBand === 'Low'
              ? 'border-blue-500 bg-blue-500/20 ring-1 ring-blue-500'
              : 'border-slate-800 bg-[#0f1822] hover:border-slate-700'
          }`}
        >
          <div className="text-[11px] font-bold uppercase tracking-wider text-blue-400">
            Low Priority
          </div>
          <div className="mt-2 text-2xl font-bold text-white">{bandCounts.Low}</div>
          <div className="mt-1 text-[11px] text-slate-400">No Path &bull; Triaged Fixed</div>
        </button>
      </div>

      {/* Ranked Findings List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="flex flex-col items-center justify-center p-12 text-slate-400">
            <Loader2 className="h-8 w-8 animate-spin text-sky-400" />
            <span className="mt-3 text-xs">Loading deterministic priority rankings from backend...</span>
          </div>
        ) : error ? (
          <div className="rounded-xl border border-rose-900/50 bg-[#160b0e] p-8 text-center text-xs text-rose-300">
            <ShieldAlert className="mx-auto h-8 w-8 text-rose-400 mb-2" />
            <h3 className="font-semibold text-white">Error Loading Risk Priorities</h3>
            <p className="mt-1 text-rose-400">{error}</p>
          </div>
        ) : filteredRanked.length === 0 ? (
          <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
            <Info className="mx-auto h-8 w-8 text-slate-500 mb-2" />
            <h3 className="font-semibold text-white">No findings in selected band</h3>
            <p className="mt-1 text-slate-500">
              {findings.length === 0
                ? 'No vulnerability findings have been matched for this project.'
                : 'Click "All" or another priority band to inspect other findings.'}
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {filteredRanked.map((item) => (
              <div
                key={item.id}
                className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-3">
                    <span
                      className={`rounded px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider ${
                        item.priority.toLowerCase() === 'highest'
                          ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                          : item.priority.toLowerCase() === 'high'
                          ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                          : item.priority.toLowerCase() === 'medium'
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                          : item.priority.toLowerCase() === 'low'
                          ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                          : 'bg-slate-700/40 text-slate-300 border border-slate-600'
                      }`}
                    >
                      {item.priority} Priority
                    </span>
                    <span className="font-mono font-bold text-white text-sm">{item.advisory_id}</span>
                    <span className="text-xs text-slate-300 font-semibold font-mono">
                      {item.package_name}@{item.package_version}
                    </span>
                    <span className="text-xs text-slate-400">
                      Service: <strong className="text-slate-200">{item.service_name}</strong>
                    </span>
                    {item.scoring_version && (
                      <span className="rounded bg-slate-800/80 px-2 py-0.5 text-[10px] font-mono text-slate-400 border border-slate-700/60">
                        Policy: {item.scoring_version}
                      </span>
                    )}
                  </div>

                  <Link
                    to={`/findings/${item.id}`}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-sky-400 hover:text-sky-300"
                  >
                    <span>Inspect Finding</span>
                    <ArrowRight className="h-3 w-3" />
                  </Link>
                </div>

                <p className="text-xs text-slate-300">{item.advisory_summary || 'No advisory summary provided.'}</p>

                {/* Deterministic Scoring Reasons (US-301) */}
                {item.priority_reasons && item.priority_reasons.length > 0 && (
                  <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3">
                    <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
                      Ranking Decision Reasons (docs/scoring.md):
                    </div>
                    <ul className="space-y-1.5 text-xs text-slate-300">
                      {item.priority_reasons.map((r, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="mt-1 h-1.5 w-1.5 rounded-full bg-sky-400 shrink-0" />
                          <span>{r}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
