import { useState, useEffect } from 'react'
import {
  CheckSquare,
  Loader2,
  CheckCircle2,
} from 'lucide-react'
import { Link } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import { getProjectVulnerabilities } from '@/features/projects/projectApi'
import type { VulnerabilityFinding } from '@/features/projects/types'

type DecisionStatus = 'open' | 'under_investigation' | 'affected' | 'not_affected' | 'fixed'

interface FindingDecision {
  status: DecisionStatus
  justification?: string
  decidedAt: number
}

const STORAGE_DECISIONS_KEY = 'vulnify_triage_decisions'

function getStoredDecisions(): Record<string, FindingDecision> {
  try {
    const raw = localStorage.getItem(STORAGE_DECISIONS_KEY)
    return raw ? JSON.parse(raw) : {}
  } catch {
    return {}
  }
}

function saveStoredDecision(findingId: string, decision: FindingDecision) {
  try {
    const current = getStoredDecisions()
    current[findingId] = decision
    localStorage.setItem(STORAGE_DECISIONS_KEY, JSON.stringify(current))
  } catch {
    // Ignore storage errors
  }
}

export function ReviewQueuePage() {
  const { activeProject } = useProjects()

  const [findings, setFindings] = useState<VulnerabilityFinding[]>([])
  const [decisions, setDecisions] = useState<Record<string, FindingDecision>>({})
  const [activeTab, setActiveTab] = useState<DecisionStatus | 'ALL'>('ALL')
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFinding | null>(null)
  const [decisionInput, setDecisionInput] = useState<DecisionStatus>('affected')
  const [justification, setJustification] = useState('')
  const [justificationError, setJustificationError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)

  useEffect(() => {
    setDecisions(getStoredDecisions())
  }, [])

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

  const handleRecordDecision = (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedFinding) return

    if (decisionInput === 'not_affected' && !justification.trim()) {
      setJustificationError('A written justification is required when marking a finding as "Not Affected" (US-401).')
      return
    }

    const newDecision: FindingDecision = {
      status: decisionInput,
      justification: justification.trim() || undefined,
      decidedAt: Math.floor(Date.now() / 1000),
    }

    saveStoredDecision(selectedFinding.id, newDecision)
    setDecisions((prev) => ({ ...prev, [selectedFinding.id]: newDecision }))
    setSelectedFinding(null)
    setJustification('')
    setJustificationError(null)
  }

  const getStatus = (findingId: string): DecisionStatus => {
    return decisions[findingId]?.status || 'open'
  }

  const filteredFindings = findings.filter((f) => {
    if (activeTab === 'ALL') return true
    return getStatus(f.id) === activeTab
  })

  if (!activeProject) {
    return (
      <div className="rounded-xl border border-dashed border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
        <h2 className="text-sm font-bold text-white">No Active Project Selected</h2>
        <p className="mt-1">Please select an active project to view the review queue.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-white">Security Review Queue</h1>
            <span className="rounded-full bg-sky-500/20 border border-sky-500/30 px-2.5 py-0.5 text-xs font-semibold text-sky-300">
              US-401 &bull; Triage Decisions
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Capture human judgment on findings for{' '}
            <span className="font-semibold text-slate-200">{activeProject.name}</span>. Marked
            decisions are permanently logged with timestamps and justification.
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-slate-800 bg-[#0f1822] p-2 text-xs">
        {(['ALL', 'open', 'under_investigation', 'affected', 'not_affected', 'fixed'] as const).map(
          (tab) => {
            const count =
              tab === 'ALL'
                ? findings.length
                : findings.filter((f) => getStatus(f.id) === tab).length
            return (
              <button
                key={tab}
                type="button"
                onClick={() => setActiveTab(tab)}
                className={`rounded-lg px-3 py-1.5 font-semibold capitalize transition-colors ${
                  activeTab === tab
                    ? 'bg-sky-500 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                {tab.replace('_', ' ')} ({count})
              </button>
            )
          },
        )}
      </div>

      {/* Findings Triage List */}
      <div className="space-y-3">
        {isLoading ? (
          <div className="flex flex-col items-center justify-center p-12 text-slate-400">
            <Loader2 className="h-8 w-8 animate-spin text-sky-400" />
            <span className="mt-3 text-xs">Loading review queue...</span>
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
            <CheckCircle2 className="mx-auto h-8 w-8 text-emerald-400 mb-2" />
            <h3 className="font-semibold text-white">No findings in this review state</h3>
            <p className="mt-1 text-slate-500">
              Select "All" or another tab to review findings in other statuses.
            </p>
          </div>
        ) : (
          filteredFindings.map((f) => {
            const currentDecision = decisions[f.id]
            const currentStatus = currentDecision?.status || 'open'

            return (
              <div
                key={f.id}
                className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span className="font-mono font-bold text-white text-sm">{f.id}</span>
                    <span className="font-semibold text-slate-200 text-xs">
                      {f.package_name}@{f.package_version}
                    </span>
                    <span
                      className={`rounded-full px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                        currentStatus === 'open'
                          ? 'bg-amber-500/15 border border-amber-500/30 text-amber-300'
                          : currentStatus === 'fixed'
                          ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-300'
                          : currentStatus === 'not_affected'
                          ? 'bg-slate-800 text-slate-400'
                          : 'bg-sky-500/15 border border-sky-500/30 text-sky-300'
                      }`}
                    >
                      Status: {currentStatus.replace('_', ' ')}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setSelectedFinding(f)
                        setDecisionInput(currentStatus)
                        setJustification(currentDecision?.justification || '')
                        setJustificationError(null)
                      }}
                      className="rounded-lg bg-sky-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-400 transition-colors"
                    >
                      Record Decision
                    </button>
                    <Link
                      to={`/findings/${f.id}`}
                      className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-700 hover:text-white"
                    >
                      Evidence
                    </Link>
                  </div>
                </div>

                <p className="text-xs text-slate-300">{f.summary}</p>

                {currentDecision && (
                  <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 text-xs text-slate-400 flex items-center justify-between">
                    <div>
                      <strong>Logged Decision: </strong>
                      <span className="text-white capitalize">
                        {currentDecision.status.replace('_', ' ')}
                      </span>
                      {currentDecision.justification && (
                        <span className="text-slate-400 ml-2 italic">
                          &mdash; "{currentDecision.justification}"
                        </span>
                      )}
                    </div>
                    <span className="text-[11px] text-slate-500">
                      {new Date(currentDecision.decidedAt * 1000).toLocaleString()}
                    </span>
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>

      {/* Decision Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-2xl">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <CheckSquare className="h-4 w-4 text-sky-400" />
              <span>Record Triage Decision &bull; {selectedFinding.id}</span>
            </h2>
            <p className="mt-1 text-xs text-slate-400">
              Target package: {selectedFinding.package_name}@{selectedFinding.package_version}
            </p>

            <form onSubmit={handleRecordDecision} className="mt-4 space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Select Decision Status
                </label>
                <select
                  value={decisionInput}
                  onChange={(e) => setDecisionInput(e.target.value as DecisionStatus)}
                  className="w-full rounded-lg border border-slate-700 bg-[#0b121a] p-2.5 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
                >
                  <option value="affected">Affected &mdash; Confirmed security exposure</option>
                  <option value="under_investigation">Under Investigation &mdash; In progress</option>
                  <option value="not_affected">Not Affected &mdash; Mitigated / unreachable (Requires justification)</option>
                  <option value="fixed">Fixed &mdash; Remediation applied</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Written Justification {decisionInput === 'not_affected' && <span className="text-rose-400">*</span>}
                </label>
                <textarea
                  rows={3}
                  value={justification}
                  onChange={(e) => setJustification(e.target.value)}
                  placeholder="Explain why this finding is classified under this status..."
                  className="w-full rounded-lg border border-slate-700 bg-[#0b121a] p-2.5 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
                />
                {justificationError && (
                  <p className="mt-1 text-xs text-rose-400">{justificationError}</p>
                )}
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setSelectedFinding(null)}
                  className="rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-400"
                >
                  Save Decision
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
