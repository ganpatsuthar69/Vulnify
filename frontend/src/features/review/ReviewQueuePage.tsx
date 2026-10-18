import { useState, useEffect, useCallback } from 'react'
import {
  CheckSquare,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  ShieldAlert,
  Check,
} from 'lucide-react'
import { Link } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import {
  getProjectFindings,
  recordFindingDecision,
  reviewFindingDecision,
  detectDecisionChanges,
} from '@/features/projects/projectApi'
import type { FindingItem, FindingTriageStatus } from '@/features/projects/types'

type QueueTab = 'ALL' | 'NEEDS_REVIEW' | 'open' | 'under_investigation' | 'affected' | 'not_affected' | 'fixed'

export function ReviewQueuePage() {
  const { activeProject } = useProjects()

  const [findings, setFindings] = useState<FindingItem[]>([])
  const [activeTab, setActiveTab] = useState<QueueTab>('ALL')
  const [selectedFinding, setSelectedFinding] = useState<FindingItem | null>(null)
  const [decisionInput, setDecisionInput] = useState<FindingTriageStatus>('affected')
  const [justification, setJustification] = useState('')
  const [justificationError, setJustificationError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isScanning, setIsScanning] = useState(false)
  const [notification, setNotification] = useState<{ type: 'success' | 'info'; message: string } | null>(null)

  const loadFindings = useCallback(async () => {
    if (!activeProject) return
    setIsLoading(true)
    try {
      const response = await getProjectFindings(activeProject.id, { page_size: 100 })
      setFindings(response.items)
    } catch (err) {
      console.error('Failed to load project findings for review queue:', err)
    } finally {
      setIsLoading(false)
    }
  }, [activeProject])

  useEffect(() => {
    void loadFindings()
  }, [loadFindings])

  const handleScanChanges = async () => {
    if (!activeProject) return
    setIsScanning(true)
    setNotification(null)
    try {
      const result = await detectDecisionChanges(activeProject.id)
      await loadFindings()
      if (result.flagged_count > 0) {
        setNotification({
          type: 'info',
          message: `Change detection completed: ${result.flagged_count} decision(s) flagged for review due to underlying evidence changes.`,
        })
      } else {
        setNotification({
          type: 'success',
          message: `Change detection completed: All ${result.evaluated_count} settled decisions are quiet and consistent with current evidence.`,
        })
      }
    } catch {
      setNotification({
        type: 'info',
        message: 'Failed to run change detection across decisions.',
      })
    } finally {
      setIsScanning(false)
    }
  }

  const handleRecordDecision = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!activeProject || !selectedFinding) return

    if (decisionInput === 'not_affected' && justification.trim().length < 10) {
      setJustificationError('A written justification of at least 10 characters is required when marking a finding as "Not Affected".')
      return
    }

    setIsSubmitting(true)
    try {
      await recordFindingDecision(activeProject.id, selectedFinding.id, {
        status: decisionInput,
        justification: justification.trim() || undefined,
      })
      await loadFindings()
      setSelectedFinding(null)
      setJustification('')
      setJustificationError(null)
      setNotification({
        type: 'success',
        message: `Triage decision recorded successfully for ${selectedFinding.advisory_id}.`,
      })
    } catch (err) {
      setJustificationError(err instanceof Error ? err.message : 'Failed to record decision.')
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleConfirmDecision = async (finding: FindingItem) => {
    if (!activeProject) return
    setIsSubmitting(true)
    try {
      await reviewFindingDecision(activeProject.id, finding.id, {
        action: 'confirm',
      })
      await loadFindings()
      setNotification({
        type: 'success',
        message: `Decision reaffirmed and baseline updated for ${finding.advisory_id}. Review flag cleared.`,
      })
    } catch (err) {
      setNotification({
        type: 'info',
        message: err instanceof Error ? err.message : 'Failed to confirm decision.',
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  const needsReviewCount = findings.filter((f) => Boolean(f.review_required)).length

  const filteredFindings = findings.filter((f) => {
    if (activeTab === 'ALL') return true
    if (activeTab === 'NEEDS_REVIEW') return Boolean(f.review_required)
    return f.status === activeTab
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
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Review and capture decisions for{' '}
            <span className="font-semibold text-slate-200">{activeProject.name}</span>. Settled findings stay quiet unless
            advisory, version, or dependency path changes.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleScanChanges}
            disabled={isScanning}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:bg-slate-700 hover:text-white disabled:opacity-50 transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isScanning ? 'animate-spin text-sky-400' : 'text-slate-400'}`} />
            <span>{isScanning ? 'Evaluating...' : 'Scan for Changes'}</span>
          </button>
        </div>
      </div>

      {/* Notification Toast/Banner */}
      {notification && (
        <div
          className={`flex items-center justify-between rounded-lg border p-3.5 text-xs ${
            notification.type === 'success'
              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
              : 'border-sky-500/30 bg-sky-500/10 text-sky-300'
          }`}
        >
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>{notification.message}</span>
          </div>
          <button
            type="button"
            onClick={() => setNotification(null)}
            className="text-slate-400 hover:text-white"
          >
            &times;
          </button>
        </div>
      )}

      {/* Needs Review Alert Banner */}
      {needsReviewCount > 0 && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 shadow-sm flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="text-xs">
            <h2 className="font-bold text-rose-200 text-sm">
              {needsReviewCount} Settled Finding{needsReviewCount > 1 ? 's' : ''} Require Review
            </h2>
            <p className="mt-1 text-rose-300/90 leading-relaxed">
              Underlying evidence (such as advisory severity, affected range, fixed release, installed package version,
              or dependency reachability) has changed since previous decisions were recorded. Click the{' '}
              <button
                type="button"
                onClick={() => setActiveTab('NEEDS_REVIEW')}
                className="font-bold underline hover:text-white"
              >
                Needs Review
              </button>{' '}
              tab to inspect differences and confirm or re-triage.
            </p>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-slate-800 bg-[#0f1822] p-2 text-xs">
        {(
          [
            { key: 'ALL', label: 'All Findings', count: findings.length, isAlert: false },
            { key: 'NEEDS_REVIEW', label: 'Needs Review', count: needsReviewCount, isAlert: needsReviewCount > 0 },
            { key: 'open', label: 'Open', count: findings.filter((f) => f.status === 'open').length, isAlert: false },
            { key: 'under_investigation', label: 'Under Investigation', count: findings.filter((f) => f.status === 'under_investigation').length, isAlert: false },
            { key: 'not_affected', label: 'Not Affected', count: findings.filter((f) => f.status === 'not_affected').length, isAlert: false },
            { key: 'affected', label: 'Affected', count: findings.filter((f) => f.status === 'affected').length, isAlert: false },
            { key: 'fixed', label: 'Fixed', count: findings.filter((f) => f.status === 'fixed').length, isAlert: false },
          ] as const
        ).map((tab) => {
          const isActive = activeTab === tab.key
          return (
            <button
              key={tab.key}
              type="button"
              onClick={() => setActiveTab(tab.key)}
              className={`rounded-lg px-3 py-1.5 font-semibold transition-colors flex items-center gap-1.5 ${
                isActive
                  ? tab.isAlert
                    ? 'bg-rose-600 text-white shadow-sm'
                    : 'bg-sky-500 text-white shadow-sm'
                  : tab.isAlert
                  ? 'border border-rose-500/40 bg-rose-500/15 text-rose-300 hover:bg-rose-500/25'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <span>{tab.label}</span>
              <span
                className={`rounded-full px-1.5 py-0.2 text-[10px] ${
                  isActive ? 'bg-black/20 text-white' : tab.isAlert ? 'bg-rose-500/30 text-rose-200' : 'bg-slate-800 text-slate-300'
                }`}
              >
                {tab.count}
              </span>
            </button>
          )
        })}
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
              {activeTab === 'NEEDS_REVIEW'
                ? 'All settled decisions are quiet and consistent with authoritative evidence.'
                : 'Select "All Findings" or another tab to review findings.'}
            </p>
          </div>
        ) : (
          filteredFindings.map((f) => {
            const isFlagged = Boolean(f.review_required)
            const currentStatus = f.status || 'open'

            return (
              <div
                key={f.id}
                className={`rounded-xl border p-5 shadow-xl space-y-3 transition-colors ${
                  isFlagged
                    ? 'border-rose-500/40 bg-[#16121a]'
                    : 'border-slate-800 bg-[#0f1822]'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <span className="font-mono font-bold text-white text-sm">{f.advisory_id}</span>
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
                          ? 'bg-slate-800 border border-slate-700 text-slate-300'
                          : 'bg-sky-500/15 border border-sky-500/30 text-sky-300'
                      }`}
                    >
                      Status: {currentStatus.replace('_', ' ')}
                    </span>

                    {/* Needs Review Badge */}
                    {isFlagged && (
                      <span className="rounded-full bg-rose-500/20 border border-rose-500/40 px-2.5 py-0.5 text-[10px] font-bold text-rose-300 flex items-center gap-1">
                        <AlertTriangle className="h-3 w-3" />
                        <span>Needs Review</span>
                      </span>
                    )}

                    {/* Priority */}
                    <span className="rounded border border-slate-800 bg-slate-900 px-2 py-0.5 text-[10px] font-mono text-slate-400">
                      Priority: {f.priority}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    {isFlagged ? (
                      <>
                        <button
                          type="button"
                          onClick={() => handleConfirmDecision(f)}
                          disabled={isSubmitting}
                          className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500 disabled:opacity-50 transition-colors shadow-sm"
                          title="Acknowledge detected change, keep decision settled, and advance evidence baseline"
                        >
                          <Check className="h-3.5 w-3.5" />
                          <span>Review &amp; Confirm</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedFinding(f)
                            setDecisionInput(currentStatus)
                            setJustification(f.triage_justification || '')
                            setJustificationError(null)
                          }}
                          className="rounded-lg bg-sky-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-400 transition-colors"
                        >
                          Re-triage
                        </button>
                      </>
                    ) : (
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedFinding(f)
                          setDecisionInput(currentStatus)
                          setJustification(f.triage_justification || '')
                          setJustificationError(null)
                        }}
                        className="rounded-lg bg-sky-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-400 transition-colors"
                      >
                        Record Decision
                      </button>
                    )}
                    <Link
                      to={`/findings/${encodeURIComponent(f.id)}`}
                      className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-700 hover:text-white"
                    >
                      Evidence
                    </Link>
                  </div>
                </div>

                <p className="text-xs text-slate-300">{f.advisory_summary}</p>

                {/* Detected Change Box for Flagged Decisions */}
                {isFlagged && f.review_reason && (
                  <div className="rounded-lg border border-rose-500/30 bg-rose-950/20 p-3 text-xs text-rose-200 flex items-start gap-2.5">
                    <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
                    <div className="space-y-1">
                      <div className="font-semibold text-rose-300">Evidence Difference Detected:</div>
                      <p className="text-rose-200/90 leading-relaxed">{f.review_reason}</p>
                    </div>
                  </div>
                )}

                {/* Logged Decision & Audit Metadata */}
                {(f.triage_justification || f.triaged_at) && (
                  <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 text-xs text-slate-400 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div>
                      <strong>Logged Decision: </strong>
                      <span className="text-white capitalize">
                        {currentStatus.replace('_', ' ')}
                      </span>
                      {f.triaged_by && (
                        <span className="text-slate-400 ml-1">
                          by <span className="text-slate-300">{f.triaged_by}</span>
                        </span>
                      )}
                      {f.triage_justification && (
                        <div className="mt-1 text-slate-300 italic">
                          &mdash; "{f.triage_justification}"
                        </div>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-500 sm:text-right shrink-0">
                      {f.triaged_at && (
                        <div>Decided: {new Date(f.triaged_at * 1000).toLocaleString()}</div>
                      )}
                      {f.reviewed_at && (
                        <div className="text-emerald-400/80">Reviewed: {new Date(f.reviewed_at * 1000).toLocaleString()}</div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>

      {/* Decision / Re-triage Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-2xl">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <CheckSquare className="h-4 w-4 text-sky-400" />
              <span>Record Triage Decision &bull; {selectedFinding.advisory_id}</span>
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
                  onChange={(e) => setDecisionInput(e.target.value as FindingTriageStatus)}
                  className="w-full rounded-lg border border-slate-700 bg-[#0b121a] p-2.5 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
                >
                  <option value="affected">Affected &mdash; Confirmed security exposure</option>
                  <option value="under_investigation">Under Investigation &mdash; In progress</option>
                  <option value="not_affected">Not Affected &mdash; Mitigated / unreachable (Requires justification &ge; 10 chars)</option>
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
                  onChange={(e) => {
                    setJustification(e.target.value)
                    if (justificationError) setJustificationError(null)
                  }}
                  placeholder={
                    decisionInput === 'not_affected'
                      ? 'Explain why this finding is classified as not affected (at least 10 characters required)...'
                      : 'Optional notes explaining this classification...'
                  }
                  className="w-full rounded-lg border border-slate-700 bg-[#0b121a] p-2.5 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
                />
                {justificationError && (
                  <p className="mt-1 text-xs text-rose-400 flex items-center gap-1">
                    <ShieldAlert className="h-3.5 w-3.5" />
                    <span>{justificationError}</span>
                  </p>
                )}
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => {
                    setSelectedFinding(null)
                    setJustificationError(null)
                  }}
                  className="rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-400 disabled:opacity-50"
                >
                  {isSubmitting ? 'Saving...' : 'Save Decision'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
