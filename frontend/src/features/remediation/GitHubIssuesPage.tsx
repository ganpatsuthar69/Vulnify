import { useState, useEffect, useMemo, useCallback } from 'react'
import { useSearchParams } from 'react-router'
import {
  GitPullRequest,
  CheckCircle2,
  Hash,
  Lock,
  Loader2,
  Check,
  RefreshCw,
  AlertCircle,
  ExternalLink,
  ShieldAlert,
  AlertTriangle,
  FileText,
  Clock,
  Layers,
} from 'lucide-react'
import { useProjects } from '@/features/projects/ProjectProvider'
import {
  getProjectFindings,
  getGitHubStatus,
  previewGitHubIssue,
  createGitHubIssue,
  getProjectGitHubIssues,
  ProjectApiError,
} from '@/features/projects/projectApi'
import type {
  FindingItem,
  GitHubIntegrationStatusResponse,
  GitHubIssuePreviewResponse,
  GitHubIssueRecordResponse,
} from '@/features/projects/types'

export function GitHubIssuesPage() {
  const { activeProject } = useProjects()
  const [searchParams] = useSearchParams()

  const queryFinding = searchParams.get('finding') || ''
  const queryTarget = searchParams.get('target') || ''
  const querySimId = searchParams.get('simId') || ''

  // Data states
  const [findings, setFindings] = useState<FindingItem[]>([])
  const [isLoadingFindings, setIsLoadingFindings] = useState(false)
  const [findingsError, setFindingsError] = useState<string | null>(null)

  const [integrationStatus, setIntegrationStatus] = useState<GitHubIntegrationStatusResponse | null>(null)
  const [issueHistory, setIssueHistory] = useState<GitHubIssueRecordResponse[]>([])

  // Form selections
  const [selectedFindingId, setSelectedFindingId] = useState<string>(queryFinding)
  const [targetVersion, setTargetVersion] = useState<string>(queryTarget)
  const [customTitle, setCustomTitle] = useState<string>('')
  const [hasApproved, setHasApproved] = useState(false)

  // Preview state
  const [preview, setPreview] = useState<GitHubIssuePreviewResponse | null>(null)
  const [isPreviewLoading, setIsPreviewLoading] = useState(false)
  const [previewError, setPreviewError] = useState<string | null>(null)

  // Submission state
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [submitResult, setSubmitResult] = useState<GitHubIssueRecordResponse | null>(null)
  const [submitError, setSubmitError] = useState<string | null>(null)

  // 1. Load integration status and history
  const loadStatusAndHistory = useCallback(async (projectId: string) => {
    try {
      const [status, historyRes] = await Promise.all([
        getGitHubStatus(projectId),
        getProjectGitHubIssues(projectId),
      ])
      setIntegrationStatus(status)
      setIssueHistory(historyRes.items)
    } catch {
      // Non-blocking for status
    }
  }, [])

  // 2. Load findings list
  const loadFindings = useCallback(async (projectId: string) => {
    setIsLoadingFindings(true)
    setFindingsError(null)
    try {
      const res = await getProjectFindings(projectId, { page_size: 100 })
      setFindings(res.items)
      if (res.items.length > 0) {
        if (queryFinding && res.items.some((f) => f.id === queryFinding)) {
          setSelectedFindingId(queryFinding)
        } else if (!selectedFindingId || !res.items.some((f) => f.id === selectedFindingId)) {
          setSelectedFindingId(res.items[0]!.id)
        }
      }
    } catch {
      setFindingsError('Failed to load project findings.')
    } finally {
      setIsLoadingFindings(false)
    }
  }, [queryFinding, selectedFindingId])

  useEffect(() => {
    if (activeProject) {
      void loadFindings(activeProject.id)
      void loadStatusAndHistory(activeProject.id)
    } else {
      setFindings([])
      setIssueHistory([])
      setIntegrationStatus(null)
      setPreview(null)
    }
  }, [activeProject, loadFindings, loadStatusAndHistory])

  // Current selected finding item
  const selectedFinding = useMemo(() => {
    return findings.find((f) => f.id === selectedFindingId) || null
  }, [findings, selectedFindingId])

  // Sync initial target version from query param or finding fixed version
  useEffect(() => {
    if (queryTarget) {
      setTargetVersion(queryTarget)
    } else if (selectedFinding?.fixed_version) {
      setTargetVersion(selectedFinding.fixed_version)
    }
  }, [queryTarget, selectedFinding])

  // 3. Fetch Preview from Backend
  const fetchPreview = useCallback(async (titleOverrideVal?: string) => {
    if (!activeProject || !selectedFindingId) return

    setIsPreviewLoading(true)
    setPreviewError(null)
    try {
      const prevData = await previewGitHubIssue(activeProject.id, selectedFindingId, {
        title_override: titleOverrideVal !== undefined ? titleOverrideVal : customTitle || undefined,
        target_version: targetVersion || undefined,
        target_repo: integrationStatus?.target_repo || undefined,
      })
      setPreview(prevData)
      if (titleOverrideVal === undefined && !customTitle) {
        setCustomTitle(prevData.title)
      }
    } catch (err) {
      const msg = err instanceof ProjectApiError ? err.message : 'Failed to generate issue preview.'
      setPreviewError(msg)
    } finally {
      setIsPreviewLoading(false)
    }
  }, [activeProject, selectedFindingId, customTitle, targetVersion, integrationStatus])

  // Refresh preview whenever finding selection or target version changes
  useEffect(() => {
    if (activeProject && selectedFindingId) {
      setCustomTitle('')
      setHasApproved(false)
      setSubmitResult(null)
      setSubmitError(null)
      void fetchPreview('')
    }
  }, [activeProject, selectedFindingId, targetVersion, fetchPreview])

  // Handle title edit: reset approval checkbox immediately
  const handleTitleChange = (newTitle: string) => {
    setCustomTitle(newTitle)
    setHasApproved(false)
  }

  // Update preview when user finishes editing title (blur or click)
  const handleUpdateTitlePreview = () => {
    setHasApproved(false)
    void fetchPreview(customTitle)
  }

  // 4. Approve and Submit
  const handleApproveAndSubmit = async () => {
    if (!activeProject || !selectedFindingId || !preview || !hasApproved) return

    setIsSubmitting(true)
    setSubmitError(null)
    setSubmitResult(null)

    try {
      const created = await createGitHubIssue(activeProject.id, selectedFindingId, {
        plan_hash: preview.plan_hash,
        title: preview.title,
        body: preview.body,
        target_repo: preview.target_repo,
        target_version: preview.target_version,
        confirmed: true,
      })

      setSubmitResult(created)
      // Refresh audit history
      const historyRes = await getProjectGitHubIssues(activeProject.id)
      setIssueHistory(historyRes.items)
    } catch (err) {
      if (err instanceof ProjectApiError) {
        if (err.status === 403) {
          setSubmitError(
            'Permission denied by GitHub API. Ensure the server token has "Issues: Read & Write" permission for this repository.',
          )
        } else if (err.status === 429) {
          setSubmitError('GitHub API rate limit exceeded. Please wait a few moments before retrying.')
        } else {
          setSubmitError(err.message)
        }
      } else {
        setSubmitError('An unexpected network error occurred while creating the issue.')
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white">GitHub Remediation Issues</h1>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Cryptographically bound issue previews with mandatory human approval gating before real GitHub issue creation.
          </p>
        </div>

        <button
          type="button"
          onClick={() => {
            if (activeProject) {
              void loadFindings(activeProject.id)
              void loadStatusAndHistory(activeProject.id)
            }
          }}
          disabled={isLoadingFindings || !activeProject}
          className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-700 hover:bg-slate-800 disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isLoadingFindings ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Unconfigured Token Warning (Honest Configuration State) */}
      {integrationStatus && !integrationStatus.configured && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-200">
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" aria-hidden="true" />
            <div className="space-y-1">
              <span className="font-semibold text-white">GitHub Integration Token Missing:</span>
              <p className="text-amber-200/90 leading-relaxed">
                The backend <code className="font-mono text-amber-300">GITHUB_TOKEN</code> environment variable is not configured.
                Issue preview and plan hashing are fully operational, but creating issues on GitHub will fail closed until an administrator configures the token.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Safety & CSRF Banner */}
      <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-4 text-xs text-sky-200">
        <div className="flex items-start gap-2.5">
          <Lock className="h-4 w-4 text-sky-400 mt-0.5 shrink-0" aria-hidden="true" />
          <div className="space-y-1">
            <span className="font-semibold text-white">Human Approval Gate & CSRF Integrity:</span>
            <p className="text-sky-200/90 leading-relaxed">
              Every remediation issue requires explicit human approval bound to a SHA-256 cryptographic plan hash.
              The backend requires strict CSRF verification (<code className="font-mono text-sky-300">X-Requested-With: vulnify</code>).
              Per Vulnify safety policy, raw untrusted advisory markdown is never injected unquoted into issue tickets.
            </p>
          </div>
        </div>
      </div>

      {querySimId && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-emerald-400 shrink-0" />
            <span>
              Pre-filled from Fix Simulation <code className="font-mono">{querySimId.slice(0, 8)}</code>
              {queryTarget ? ` with target version ${queryTarget}` : ''}.
            </span>
          </div>
          <span className="text-[10px] uppercase font-bold tracking-wider text-emerald-400 bg-emerald-500/20 px-2 py-0.5 rounded">
            Simulation Linked
          </span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Finding Selector & Draft Form */}
        <div className="lg:col-span-5 space-y-5">
          <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <GitPullRequest className="h-4 w-4 text-sky-400" />
              Configure Issue Draft
            </h2>

            {/* Select Finding */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Target Finding for Issue
              </label>
              {isLoadingFindings ? (
                <div className="flex items-center gap-2 text-xs text-slate-400 py-2">
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-sky-400" />
                  Loading findings...
                </div>
              ) : findingsError ? (
                <div className="flex items-center gap-2 text-xs text-red-400 py-2">
                  <AlertCircle className="h-4 w-4" />
                  <span>{findingsError}</span>
                </div>
              ) : findings.length === 0 ? (
                <div className="text-xs text-slate-400 italic">No findings available in active project.</div>
              ) : (
                <select
                  value={selectedFindingId}
                  onChange={(e) => setSelectedFindingId(e.target.value)}
                  className="w-full rounded-lg border border-slate-800 bg-[#0b121a] px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
                >
                  {findings.map((f) => (
                    <option key={f.id} value={f.id}>
                      {f.package_name}@{f.package_version} — {f.advisory_id} ({f.priority})
                    </option>
                  ))}
                </select>
              )}
            </div>

            {/* Target Version Input */}
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Target Remediation Version <span className="text-slate-500">(Optional)</span>
              </label>
              <input
                type="text"
                value={targetVersion}
                onChange={(e) => {
                  setTargetVersion(e.target.value)
                  setHasApproved(false)
                }}
                onBlur={() => void fetchPreview()}
                placeholder="e.g. 4.17.21"
                className="w-full rounded-lg border border-slate-800 bg-[#0b121a] px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
              />
            </div>

            {/* Issue Title Input */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-medium text-slate-300">
                  Issue Title <span className="text-slate-500">(Editing resets approval hash)</span>
                </label>
                {customTitle !== preview?.title && (
                  <button
                    type="button"
                    onClick={handleUpdateTitlePreview}
                    className="text-[11px] text-sky-400 hover:text-sky-300 font-medium"
                  >
                    Recompute Hash &rarr;
                  </button>
                )}
              </div>
              <input
                type="text"
                value={customTitle}
                onChange={(e) => handleTitleChange(e.target.value)}
                onBlur={handleUpdateTitlePreview}
                placeholder="Issue title..."
                className="w-full rounded-lg border border-slate-800 bg-[#0b121a] px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
              />
            </div>

            {/* Target Repository */}
            <div className="rounded-lg border border-slate-800/80 bg-[#0b121a] p-3 text-xs space-y-1">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Target Repository
              </span>
              <div className="flex items-center justify-between text-slate-300 font-mono">
                <span>{preview?.target_repo || integrationStatus?.target_repo || 'vulnify/demo-workspace'}</span>
                <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-slate-400">Configured</span>
              </div>
            </div>

            {/* Approval Checkbox Gate */}
            <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3 space-y-2">
              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={hasApproved}
                  onChange={(e) => setHasApproved(e.target.checked)}
                  disabled={!preview || isPreviewLoading || !preview.can_submit}
                  className="mt-0.5 h-4 w-4 rounded border-slate-700 bg-slate-800 text-sky-500 focus:ring-sky-500 focus:ring-offset-0 disabled:opacity-50"
                />
                <span className="text-xs text-slate-300 leading-snug">
                  I have reviewed the structured preview, verified the reachability evidence and remediation target,
                  and explicitly approve filing this issue under plan hash{' '}
                  <code className="font-mono text-sky-400">
                    {preview?.plan_hash ? `${preview.plan_hash.slice(0, 16)}...` : 'pending preview'}
                  </code>
                </span>
              </label>
            </div>

            {/* Submit Button */}
            <button
              type="button"
              disabled={!hasApproved || isSubmitting || !preview || !preview.can_submit}
              onClick={() => void handleApproveAndSubmit()}
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-sky-500 px-4 py-2.5 text-xs font-semibold text-white transition hover:bg-sky-400 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Creating Issue on GitHub...
                </>
              ) : (
                <>
                  <CheckCircle2 className="h-4 w-4" />
                  Approve & Create GitHub Issue
                </>
              )}
            </button>

            {/* Error Notification */}
            {submitError && (
              <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300 flex items-start gap-2">
                <ShieldAlert className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
                <p>{submitError}</p>
              </div>
            )}

            {/* Success / Duplicate Notification */}
            {submitResult && (
              <div
                className={`rounded-lg border p-4 text-xs space-y-2 ${
                  submitResult.is_duplicate
                    ? 'border-amber-500/30 bg-amber-500/10 text-amber-200'
                    : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
                }`}
              >
                <div className="flex items-center gap-2 font-semibold">
                  <Check className="h-4 w-4 text-emerald-400 shrink-0" />
                  <span>
                    {submitResult.is_duplicate ? 'Duplicate Issue Prevented' : 'GitHub Issue Created Successfully'}
                  </span>
                </div>
                <p className="text-slate-300 text-[11px]">{submitResult.message}</p>
                <div className="pt-1">
                  <a
                    href={submitResult.issue_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 font-semibold text-sky-400 hover:text-sky-300 underline"
                  >
                    Open Issue #{submitResult.issue_number} on GitHub ({submitResult.target_repo})
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Structured Preview & Plan Hash */}
        <div className="lg:col-span-7 space-y-5">
          <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2">
                <FileText className="h-4 w-4 text-sky-400" />
                <h2 className="text-sm font-semibold text-white">Structured Issue Preview</h2>
                <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-mono text-slate-400">
                  Markdown
                </span>
              </div>

              {/* Plan Hash Display */}
              <div className="flex items-center gap-1.5 font-mono text-[11px] text-sky-300 bg-sky-500/10 border border-sky-500/20 px-2.5 py-1 rounded">
                <Hash className="h-3 w-3 text-sky-400 shrink-0" />
                <span className="truncate max-w-[240px]">
                  {preview ? preview.plan_hash : 'no preview'}
                </span>
              </div>
            </div>

            {/* Rendered Preview Box */}
            <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 font-mono text-xs text-slate-300 leading-relaxed whitespace-pre-wrap max-h-[420px] overflow-y-auto">
              {isPreviewLoading ? (
                <div className="flex items-center justify-center py-12 text-slate-400 gap-2">
                  <Loader2 className="h-4 w-4 animate-spin text-sky-400" />
                  <span>Generating authoritative preview & SHA-256 plan hash...</span>
                </div>
              ) : previewError ? (
                <div className="text-red-400 py-4 flex items-center gap-2">
                  <AlertCircle className="h-4 w-4 shrink-0" />
                  <span>{previewError}</span>
                </div>
              ) : preview ? (
                preview.body
              ) : (
                'Select a finding to preview remediation issue.'
              )}
            </div>

            <div className="text-[11px] text-slate-500 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span>* Preview generated from verified FalkorDB graph reachability evidence.</span>
              <span className="text-slate-400">Gated by approval protocol</span>
            </div>
          </div>

          {/* Issue Audit Trail */}
          <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-3">
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Clock className="h-3.5 w-3.5 text-sky-400" />
              <span>Project Issue Action History</span>
            </h3>

            {issueHistory.length === 0 ? (
              <div className="text-xs text-slate-500 italic py-2">
                No issues prepared or created for this project yet.
              </div>
            ) : (
              <div className="divide-y divide-slate-800 max-h-60 overflow-y-auto">
                {issueHistory.map((rec) => (
                  <div key={rec.id} className="py-2.5 flex items-center justify-between text-xs gap-3">
                    <div className="min-w-0">
                      <div className="font-medium text-slate-200 truncate">{rec.title}</div>
                      <div className="font-mono text-[10px] text-slate-500 flex items-center gap-2 mt-0.5">
                        <span className="truncate max-w-[120px]">{rec.plan_hash}</span>
                        <span>&bull;</span>
                        <span>#{rec.issue_number}</span>
                        <span>&bull;</span>
                        <span>{new Date(rec.created_at * 1000).toLocaleString()}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <a
                        href={rec.issue_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 rounded bg-sky-500/15 border border-sky-500/30 px-2 py-1 text-[11px] font-medium text-sky-300 hover:bg-sky-500/25 transition"
                      >
                        GitHub #{rec.issue_number}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
