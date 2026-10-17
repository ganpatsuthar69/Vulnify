import { useState, useEffect, useMemo } from 'react'
import {
  ArrowRight,
  Loader2,
  Info,
} from 'lucide-react'
import { Link } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import { getProjectVulnerabilities } from '@/features/projects/projectApi'
import type { VulnerabilityFinding } from '@/features/projects/types'

interface RankedFinding extends VulnerabilityFinding {
  priorityBand: 'Highest' | 'High' | 'Medium' | 'Low'
  reasons: string[]
}

function computeDeterministicPriority(finding: VulnerabilityFinding): {
  band: 'Highest' | 'High' | 'Medium' | 'Low'
  reasons: string[]
} {
  const sev = finding.severity.toUpperCase()
  const hasFixed = Boolean(finding.fixed_version)
  const isAffected = finding.match_status.toLowerCase() === 'affected'
  const reasons: string[] = []

  if (sev === 'CRITICAL') {
    reasons.push('Critical severity advisory')
  } else if (sev === 'HIGH') {
    reasons.push('High severity advisory')
  } else if (['MEDIUM', 'MODERATE'].includes(sev)) {
    reasons.push('Medium/Moderate severity advisory')
  } else {
    reasons.push('Low severity advisory')
  }

  if (isAffected) {
    reasons.push('Installed version confirmed within affected range')
  } else {
    reasons.push('Reachability unconfirmed or unknown')
  }

  if (hasFixed) {
    reasons.push(`Actionable remediation available (${finding.fixed_version})`)
  } else {
    reasons.push('Remediation target unknown (no fixed version published)')
  }

  if (sev === 'CRITICAL' && isAffected) {
    return { band: 'Highest', reasons }
  }
  if (sev === 'HIGH' && isAffected) {
    return { band: 'High', reasons }
  }
  if (['MEDIUM', 'MODERATE'].includes(sev)) {
    return { band: 'Medium', reasons }
  }
  return { band: 'Low', reasons }
}

export function RiskPrioritiesPage() {
  const { activeProject } = useProjects()

  const [findings, setFindings] = useState<VulnerabilityFinding[]>([])
  const [selectedBand, setSelectedBand] = useState<string>('ALL')
  const [isLoading, setIsLoading] = useState(false)

  useEffect(() => {
    async function loadData() {
      if (!activeProject) return
      setIsLoading(true)
      try {
        const data = await getProjectVulnerabilities(activeProject.id)
        setFindings(data)
      } finally {
        setIsLoading(false)
      }
    }
    void loadData()
  }, [activeProject])

  const rankedFindings: RankedFinding[] = useMemo(() => {
    return findings.map((f) => {
      const { band, reasons } = computeDeterministicPriority(f)
      return {
        ...f,
        priorityBand: band,
        reasons,
      }
    })
  }, [findings])

  const filteredRanked = useMemo(() => {
    if (selectedBand === 'ALL') return rankedFindings
    return rankedFindings.filter((f) => f.priorityBand === selectedBand)
  }, [rankedFindings, selectedBand])

  const bandCounts = useMemo(() => {
    return {
      Highest: rankedFindings.filter((f) => f.priorityBand === 'Highest').length,
      High: rankedFindings.filter((f) => f.priorityBand === 'High').length,
      Medium: rankedFindings.filter((f) => f.priorityBand === 'Medium').length,
      Low: rankedFindings.filter((f) => f.priorityBand === 'Low').length,
    }
  }, [rankedFindings])

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
              US-301 &bull; Deterministic Scoring
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
          <div className="mt-1 text-[11px] text-slate-400">High severity &bull; Actionable</div>
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
          <div className="mt-1 text-[11px] text-slate-400">Moderate CVSS impact</div>
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
          <div className="mt-1 text-[11px] text-slate-400">Minor / informational</div>
        </button>
      </div>

      {/* Ranked Findings List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="flex flex-col items-center justify-center p-12 text-slate-400">
            <Loader2 className="h-8 w-8 animate-spin text-sky-400" />
            <span className="mt-3 text-xs">Computing deterministic priority rankings...</span>
          </div>
        ) : filteredRanked.length === 0 ? (
          <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
            <Info className="mx-auto h-8 w-8 text-slate-500 mb-2" />
            <h3 className="font-semibold text-white">No findings in selected band</h3>
            <p className="mt-1 text-slate-500">
              {rankedFindings.length === 0
                ? 'No vulnerability findings have been matched for this project.'
                : 'Click "All" or another priority band to inspect other findings.'}
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {filteredRanked.map((item) => (
              <div
                key={`${item.id}-${item.package_version_id}`}
                className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span
                      className={`rounded px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider ${
                        item.priorityBand === 'Highest'
                          ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                          : item.priorityBand === 'High'
                          ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                          : item.priorityBand === 'Medium'
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                          : 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                      }`}
                    >
                      {item.priorityBand} Priority
                    </span>
                    <span className="font-mono font-bold text-white text-sm">{item.id}</span>
                    <span className="text-xs text-slate-300 font-semibold">
                      {item.package_name}@{item.package_version}
                    </span>
                  </div>

                  <Link
                    to={`/findings/${item.id}`}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-sky-400 hover:text-sky-300"
                  >
                    <span>Inspect Finding</span>
                    <ArrowRight className="h-3 w-3" />
                  </Link>
                </div>

                <p className="text-xs text-slate-300">{item.summary}</p>

                {/* Deterministic Scoring Reasons */}
                <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3">
                  <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Ranking Decision Reasons (US-301):
                  </div>
                  <ul className="space-y-1 text-xs text-slate-300">
                    {item.reasons.map((r, i) => (
                      <li key={i} className="flex items-center gap-2">
                        <span className="h-1.5 w-1.5 rounded-full bg-sky-400" />
                        <span>{r}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
