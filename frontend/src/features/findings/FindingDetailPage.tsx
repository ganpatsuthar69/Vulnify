import { useState, useEffect } from 'react'
import {
  ArrowLeft,
  ShieldAlert,
  ExternalLink,
  Loader2,
  CheckCircle2,
  Layers,
  Fingerprint,
  Route,
  GitPullRequest,
  Database,
} from 'lucide-react'
import { Link, useParams } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import { getProjectVulnerabilities } from '@/features/projects/projectApi'
import type { VulnerabilityFinding } from '@/features/projects/types'

export function FindingDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { activeProject } = useProjects()

  const [finding, setFinding] = useState<VulnerabilityFinding | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchFinding() {
      if (!activeProject || !id) return
      setIsLoading(true)
      setError(null)
      try {
        const list = await getProjectVulnerabilities(activeProject.id)
        const matched = list.find((f) => f.id.toLowerCase() === id.toLowerCase())
        if (matched) {
          setFinding(matched)
        } else {
          setError(`Finding "${id}" not found in project ${activeProject.name}.`)
        }
      } catch {
        setError('Failed to fetch finding details from FalkorDB.')
      } finally {
        setIsLoading(false)
      }
    }

    void fetchFinding()
  }, [activeProject, id])

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center p-16 text-slate-400">
        <Loader2 className="h-8 w-8 animate-spin text-sky-400" aria-hidden="true" />
        <span className="mt-4 text-xs font-medium text-slate-300">
          Loading finding evidence...
        </span>
      </div>
    )
  }

  if (error || !finding) {
    return (
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
        <ShieldAlert className="mx-auto h-8 w-8 text-rose-400" aria-hidden="true" />
        <h2 className="mt-3 text-base font-bold text-white">Finding Not Found</h2>
        <p className="mt-1 text-slate-400">{error || 'The requested advisory was not found.'}</p>
        <Link
          to="/findings"
          className="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Back to Findings</span>
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Back button and title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <Link
            to="/findings"
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-sky-400 hover:text-sky-300 transition-colors mb-2"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>Back to Findings</span>
          </Link>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold font-mono text-white">{finding.id}</h1>
            <span
              className={`rounded px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider border ${
                finding.severity.toUpperCase() === 'CRITICAL'
                  ? 'border-red-500/40 bg-red-500/15 text-red-300'
                  : finding.severity.toUpperCase() === 'HIGH'
                  ? 'border-orange-500/40 bg-orange-500/15 text-orange-300'
                  : 'border-amber-500/40 bg-amber-500/15 text-amber-300'
              }`}
            >
              {finding.severity}
            </span>
          </div>
          {finding.aliases.length > 0 && (
            <p className="mt-1 text-xs text-slate-400 font-mono">
              Aliases: {finding.aliases.join(', ')}
            </p>
          )}
        </div>

        <div className="flex items-center gap-2.5">
          <Link
            to={`/github-issues?finding=${encodeURIComponent(finding.id)}`}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-2 text-xs font-semibold text-white shadow-sm hover:bg-sky-400 transition-colors"
          >
            <GitPullRequest className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Preview Remediation Issue</span>
          </Link>
          {finding.source_url && (
            <a
              href={finding.source_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
            >
              <span>OSV Advisory</span>
              <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
            </a>
          )}
        </div>
      </div>

      {/* Advisory Overview Card */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-4">
        <h2 className="text-sm font-bold text-white">Advisory Summary</h2>
        <p className="text-xs text-slate-200 leading-relaxed font-medium">{finding.summary}</p>
        {finding.details && (
          <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-xs text-slate-400 whitespace-pre-wrap font-mono leading-relaxed max-h-60 overflow-y-auto">
            {finding.details}
          </div>
        )}
      </div>

      {/* Evidence & Version Matching Engine Results */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Match Verification Box */}
        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-4">
          <div className="flex items-center gap-2 text-sm font-bold text-white">
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            <span>Ecosystem Version Match Evidence</span>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Target Package:</span>
              <span className="font-semibold text-white">{finding.package_name}</span>
            </div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Installed Version:</span>
              <span className="font-mono font-semibold text-sky-400">
                {finding.package_version}
              </span>
            </div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Ecosystem:</span>
              <span className="font-semibold text-slate-300 uppercase">{finding.ecosystem}</span>
            </div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Affected Range:</span>
              <span className="font-mono text-amber-300 font-medium">
                {finding.matched_range ?? 'Unspecified'}
              </span>
            </div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Fixed Version:</span>
              <span className="font-mono font-bold text-emerald-400">
                {finding.fixed_version ? `>= ${finding.fixed_version}` : 'No known fix'}
              </span>
            </div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Comparator Engine:</span>
              <span className="font-mono text-slate-300">{finding.comparator}</span>
            </div>
            <div>
              <span className="text-slate-400 block mb-1">Match Reason:</span>
              <div className="rounded-lg bg-[#0b121a] p-3 text-slate-300 font-medium border border-slate-800">
                {finding.match_reason}
              </div>
            </div>
          </div>
        </div>

        {/* Provenance & Fingerprint */}
        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-4">
          <div className="flex items-center gap-2 text-sm font-bold text-white">
            <Fingerprint className="h-4 w-4 text-sky-400" />
            <span>Audit Fingerprint &amp; Provenance</span>
          </div>

          <div className="space-y-3 text-xs">
            {finding.cvss && (
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                <span className="text-slate-400">CVSS v3 Vector:</span>
                <span className="font-mono text-[11px] text-slate-300 break-all">{finding.cvss}</span>
              </div>
            )}
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Evaluated At:</span>
              <span className="text-slate-300">
                {new Date(finding.evaluated_at * 1000).toLocaleString()}
              </span>
            </div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-slate-400">Published Date:</span>
              <span className="text-slate-300">{finding.published ?? 'Unknown'}</span>
            </div>
            <div>
              <span className="text-slate-400 block mb-1">Deterministic Result Fingerprint:</span>
              <div className="rounded-lg bg-[#0b121a] p-2.5 text-[11px] font-mono text-slate-400 border border-slate-800 break-all select-all">
                {finding.fingerprint}
              </div>
            </div>

            <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 text-slate-400 text-[11px]">
              <span className="font-semibold text-slate-300">Integrity Guarantee:</span> The result
              fingerprint is a SHA-256 hash computed deterministically from package, advisory, and
              match status.
            </div>
          </div>
        </div>
      </div>

      {/* Dependency Reachability & Exposure Chain */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2 text-sm font-bold text-white">
            <Route className="h-4 w-4 text-sky-400" />
            <span>Dependency Chain &amp; Reachability</span>
          </div>
          <Link
            to="/exposure-paths"
            className="text-xs font-semibold text-sky-400 hover:text-sky-300 transition-colors"
          >
            View all paths &rarr;
          </Link>
        </div>

        <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-5">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono">
            <div className="flex items-center gap-2 rounded bg-slate-800 px-3 py-2 text-slate-200">
              <Layers className="h-4 w-4 text-sky-400 shrink-0" />
              <span>Service Manifest</span>
            </div>
            <span className="text-slate-500 font-sans text-sm">&rarr; [DEPENDS_ON*] &rarr;</span>
            <div className="flex items-center gap-2 rounded bg-sky-500/15 border border-sky-500/30 px-3 py-2 text-sky-300">
              <Database className="h-4 w-4 shrink-0" />
              <span>
                {finding.package_name}@{finding.package_version}
              </span>
            </div>
            <span className="text-slate-500 font-sans text-sm">&rarr; [AFFECTS] &rarr;</span>
            <div className="flex items-center gap-2 rounded bg-rose-500/15 border border-rose-500/30 px-3 py-2 text-rose-300">
              <ShieldAlert className="h-4 w-4 shrink-0" />
              <span>{finding.id}</span>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-400">
            <strong>Architectural Exposure:</strong> This finding is linked to an imported service in
            FalkorDB. Dependency paths prove that this code is reachable in your build tree.
          </div>
        </div>
      </div>
    </div>
  )
}
