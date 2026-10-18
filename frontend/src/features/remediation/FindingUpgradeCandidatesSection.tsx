import { useState, useEffect } from 'react'
import {
  ArrowUpCircle,
  AlertTriangle,
  ShieldAlert,
  Loader2,
  GitPullRequest,
  Info,
} from 'lucide-react'
import { Link } from 'react-router'
import { getFindingUpgradeCandidates, ProjectApiError } from '@/features/projects/projectApi'
import type { UpgradeCandidatesResponse } from '@/features/projects/types'

interface FindingUpgradeCandidatesSectionProps {
  projectId: string
  findingId: string
}

export function FindingUpgradeCandidatesSection({
  projectId,
  findingId,
}: FindingUpgradeCandidatesSectionProps) {
  const [data, setData] = useState<UpgradeCandidatesResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let isMounted = true

    async function loadCandidates() {
      setIsLoading(true)
      setError(null)
      try {
        const res = await getFindingUpgradeCandidates(projectId, findingId)
        if (isMounted) {
          setData(res)
        }
      } catch (err) {
        if (!isMounted) return
        if (err instanceof ProjectApiError) {
          setError(err.message)
        } else {
          setError('Failed to evaluate upgrade candidates from server.')
        }
      } finally {
        if (isMounted) {
          setIsLoading(false)
        }
      }
    }

    void loadCandidates()

    return () => {
      isMounted = false
    }
  }, [projectId, findingId])

  if (isLoading) {
    return (
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-8 text-center text-slate-400">
        <Loader2 className="mx-auto h-6 w-6 animate-spin text-sky-400" aria-hidden="true" />
        <p className="mt-3 text-xs">Evaluating advisory fixed versions and SemVer upgrade targets...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-6 text-xs text-red-300">
        <div className="flex items-center gap-2 font-semibold">
          <AlertTriangle className="h-4 w-4 text-red-400" aria-hidden="true" />
          <span>Unable to Load Upgrade Candidates</span>
        </div>
        <p className="mt-1 text-slate-300">{error}</p>
      </div>
    )
  }

  if (!data) return null

  return (
    <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-2.5">
          <ArrowUpCircle className="h-5 w-5 text-emerald-400" aria-hidden="true" />
          <div>
            <h2 className="text-sm font-bold text-white">Suggested Upgrade Targets (US-401)</h2>
            <p className="text-[11px] text-slate-400">
              Targets derived strictly from upstream advisory fixed versions. Never assumed safe without testing.
            </p>
          </div>
        </div>

        {data.has_fix && (
          <span className="self-start sm:self-auto rounded bg-emerald-500/15 border border-emerald-500/30 px-2.5 py-0.5 text-xs font-semibold text-emerald-300">
            {data.candidates.length} Candidate{data.candidates.length > 1 ? 's' : ''} Available
          </span>
        )}
      </div>

      {/* AC-3: Honest No Fix Available State */}
      {!data.has_fix ? (
        <div className="rounded-xl border border-slate-700/80 bg-[#0b121a] p-6 text-center space-y-3">
          <ShieldAlert className="mx-auto h-10 w-10 text-amber-400/90" aria-hidden="true" />
          <div>
            <h3 className="text-sm font-bold text-white">No Fix Available</h3>
            <p className="mt-1.5 text-xs text-slate-300 max-w-xl mx-auto leading-relaxed">
              {data.no_fix_message ||
                'No fixed version published in advisory. No verified remediation target available.'}
            </p>
          </div>

          {data.remediation_guidance && (
            <div className="mt-4 text-left rounded-lg border border-slate-800 bg-slate-900/60 p-4 max-w-xl mx-auto space-y-1.5 text-xs text-slate-300">
              <span className="font-semibold text-slate-200 block">Recommended Defensive Actions:</span>
              <p className="text-[11px] leading-relaxed text-slate-400">
                {data.remediation_guidance}
              </p>
            </div>
          )}
        </div>
      ) : (
        /* AC-1 & AC-2: Candidates List with Classifications and Compatibility Caveats */
        <div className="space-y-4">
          <div className="grid gap-4">
            {data.candidates.map((cand) => {
              const isMajor = cand.semver_diff === 'major'
              const isPatch = cand.semver_diff === 'patch'
              const isRec = cand.is_recommended

              return (
                <div
                  key={cand.target_version}
                  className={`rounded-lg border p-4 transition-colors ${
                    isRec
                      ? 'border-emerald-500/40 bg-emerald-950/10'
                      : 'border-slate-800 bg-[#0b121a]'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-base font-bold text-white">
                          v{cand.target_version}
                        </span>

                        {/* AC-1: Labelled Recommended, Major version, or Patch only */}
                        {isRec && (
                          <span className="rounded bg-emerald-500/20 border border-emerald-500/40 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-emerald-300">
                            Recommended Target
                          </span>
                        )}
                        {isPatch && (
                          <span className="rounded bg-sky-500/20 border border-sky-500/40 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-sky-300">
                            Patch Only
                          </span>
                        )}
                        {isMajor && (
                          <span className="rounded bg-amber-500/20 border border-amber-500/40 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-amber-300 flex items-center gap-1">
                            <AlertTriangle className="h-3 w-3" />
                            Major Version Jump
                          </span>
                        )}
                        {!isMajor && !isPatch && (
                          <span className="rounded bg-slate-700/50 border border-slate-600 px-2 py-0.5 text-[10px] font-medium text-slate-300 capitalize">
                            {cand.label}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-2 text-xs text-slate-400">
                        <span>Installed: <strong className="text-slate-300 font-mono">v{data.current_version}</strong></span>
                        <span>&rarr;</span>
                        <span>Target: <strong className="text-emerald-400 font-mono">v{cand.target_version}</strong></span>
                        <span>•</span>
                        <span className="capitalize">Delta: {cand.semver_diff}</span>
                      </div>
                    </div>

                    <Link
                      to={`/github-issues?finding=${encodeURIComponent(findingId)}&target=${encodeURIComponent(cand.target_version)}`}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:bg-slate-700 hover:text-white transition-colors self-start sm:self-auto shrink-0"
                    >
                      <GitPullRequest className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>Prepare Fix Issue</span>
                    </Link>
                  </div>

                  {/* AC-2: Compatibility Caveats */}
                  {cand.caveats && cand.caveats.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-1.5">
                      <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block">
                        Compatibility Caveats &amp; Evidence:
                      </span>
                      <ul className="space-y-1 text-xs text-slate-300">
                        {cand.caveats.map((caveat, cIdx) => (
                          <li key={cIdx} className="flex items-start gap-2">
                            <span className="mt-1 h-1.5 w-1.5 rounded-full bg-slate-500 shrink-0" />
                            <span className="leading-relaxed">{caveat}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* AC-2: Mandatory Safety Disclaimer - Tool NEVER claims an upgrade is safe to ship */}
      <div className="rounded-lg border border-slate-800 bg-[#080d12] p-4 text-xs text-slate-400 flex items-start gap-3">
        <Info className="h-4 w-4 text-sky-400 mt-0.5 shrink-0" aria-hidden="true" />
        <div className="space-y-1">
          <span className="font-semibold text-slate-300">Safety Guarantee &amp; Disclaimer:</span>
          <p className="text-[11px] leading-relaxed text-slate-400">
            {data.safety_disclaimer}
          </p>
        </div>
      </div>
    </div>
  )
}
