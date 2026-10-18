import {
  UploadCloud,
  ShieldAlert,
  Cpu,
  AlertCircle,
  ArrowRight,
  ArrowLeft,
  ChevronRight,
} from 'lucide-react'
import { Link, useSearchParams } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import { LockfileImportCard } from '@/features/dependencies/LockfileImportCard'
import { OsvAdvisoryCard } from '@/features/advisories/OsvAdvisoryCard'
import { VersionMatchingCard } from '@/features/advisories/VersionMatchingCard'

type IngestionTab = 'lockfile' | 'osv' | 'matching'

export function ImportDataPage() {
  const { activeProject } = useProjects()
  const [searchParams, setSearchParams] = useSearchParams()
  const rawTab = searchParams.get('tab')
  const activeTab: IngestionTab =
    rawTab === 'osv' || rawTab === 'matching' ? rawTab : 'lockfile'

  const handleSelectTab = (tab: IngestionTab) => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        next.set('tab', tab)
        return next
      },
      { replace: true }
    )
  }

  if (!activeProject) {
    return (
      <div className="rounded-xl border border-dashed border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
        <AlertCircle className="mx-auto h-8 w-8 text-amber-400" aria-hidden="true" />
        <h2 className="mt-3 text-sm font-bold text-white">No Active Project Selected</h2>
        <p className="mt-1 text-slate-400">
          Please select or create a project in the top navigation bar to manage data ingestion.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl font-bold text-white">Data Ingestion Pipeline</h1>
          <p className="mt-1 text-xs text-slate-400">
            Import service lockfiles, fetch real OSV security advisories, and execute ecosystem-aware
            version matching for{' '}
            <span className="font-semibold text-slate-200">{activeProject.name}</span> ({activeProject.ecosystem}).
          </p>
        </div>

        {/* View Mode Tabs */}
        <div className="flex items-center rounded-lg border border-slate-800 bg-slate-900/60 p-1 text-xs">
          <button
            type="button"
            onClick={() => handleSelectTab('lockfile')}
            className={`rounded-md px-3.5 py-1.5 font-medium transition-colors ${
              activeTab === 'lockfile'
                ? 'bg-sky-500 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            1. Lockfile
          </button>
          <button
            type="button"
            onClick={() => handleSelectTab('osv')}
            className={`rounded-md px-3.5 py-1.5 font-medium transition-colors ${
              activeTab === 'osv'
                ? 'bg-amber-500 text-slate-950 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            2. OSV Advisories
          </button>
          <button
            type="button"
            onClick={() => handleSelectTab('matching')}
            className={`rounded-md px-3.5 py-1.5 font-medium transition-colors ${
              activeTab === 'matching'
                ? 'bg-emerald-500 text-slate-950 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            3. Version Matching
          </button>
        </div>
      </div>

      {/* Interactive Stage Progression Stepper */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <button
          type="button"
          onClick={() => handleSelectTab('lockfile')}
          className={`flex items-center justify-between gap-3 rounded-lg border p-3.5 text-xs text-left transition ${
            activeTab === 'lockfile'
              ? 'border-sky-500/80 bg-sky-950/20 ring-1 ring-sky-500/40 shadow-lg shadow-sky-950/20'
              : 'border-slate-800 bg-[#0f1822] hover:border-slate-700 hover:bg-slate-900/60'
          }`}
        >
          <div className="flex items-center gap-3">
            <div
              className={`flex h-7 w-7 items-center justify-center rounded font-bold shrink-0 transition ${
                activeTab === 'lockfile'
                  ? 'bg-sky-500 text-white'
                  : 'bg-sky-500/15 text-sky-400'
              }`}
            >
              1
            </div>
            <div>
              <div className="font-semibold text-white">Parse &amp; Persist Graph</div>
              <div className="text-[11px] text-slate-400">Upload lockfile / manifest</div>
            </div>
          </div>
          {activeTab === 'lockfile' && (
            <span className="text-[10px] uppercase font-bold text-sky-400 bg-sky-500/10 border border-sky-500/30 px-2 py-0.5 rounded">
              Active
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => handleSelectTab('osv')}
          className={`flex items-center justify-between gap-3 rounded-lg border p-3.5 text-xs text-left transition ${
            activeTab === 'osv'
              ? 'border-amber-500/80 bg-amber-950/20 ring-1 ring-amber-500/40 shadow-lg shadow-amber-950/20'
              : 'border-slate-800 bg-[#0f1822] hover:border-slate-700 hover:bg-slate-900/60'
          }`}
        >
          <div className="flex items-center gap-3">
            <div
              className={`flex h-7 w-7 items-center justify-center rounded font-bold shrink-0 transition ${
                activeTab === 'osv'
                  ? 'bg-amber-500 text-slate-950 font-bold'
                  : 'bg-amber-500/15 text-amber-400'
              }`}
            >
              2
            </div>
            <div>
              <div className="font-semibold text-white">Ingest OSV Advisories</div>
              <div className="text-[11px] text-slate-400">Query api.osv.dev batch</div>
            </div>
          </div>
          {activeTab === 'osv' && (
            <span className="text-[10px] uppercase font-bold text-amber-400 bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 rounded">
              Active
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => handleSelectTab('matching')}
          className={`flex items-center justify-between gap-3 rounded-lg border p-3.5 text-xs text-left transition ${
            activeTab === 'matching'
              ? 'border-emerald-500/80 bg-emerald-950/20 ring-1 ring-emerald-500/40 shadow-lg shadow-emerald-950/20'
              : 'border-slate-800 bg-[#0f1822] hover:border-slate-700 hover:bg-slate-900/60'
          }`}
        >
          <div className="flex items-center gap-3">
            <div
              className={`flex h-7 w-7 items-center justify-center rounded font-bold shrink-0 transition ${
                activeTab === 'matching'
                  ? 'bg-emerald-500 text-slate-950 font-bold'
                  : 'bg-emerald-500/15 text-emerald-400'
              }`}
            >
              3
            </div>
            <div>
              <div className="font-semibold text-white">Ecosystem Matching</div>
              <div className="text-[11px] text-slate-400">Evaluate SemVer ranges</div>
            </div>
          </div>
          {activeTab === 'matching' && (
            <span className="text-[10px] uppercase font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded">
              Active
            </span>
          )}
        </button>
      </div>

      {/* Tab-Driven Stage Content */}
      <div className="space-y-4">
        {activeTab === 'lockfile' && (
          <div className="space-y-4">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <UploadCloud className="h-4 w-4 text-sky-400" />
              <span>Stage 1: Multi-Ecosystem Dependency Ingestion</span>
            </div>
            <LockfileImportCard project={activeProject} />

            {/* Stage Navigation Footer */}
            <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-[#0f1822] p-4 text-xs">
              <span className="text-slate-400">
                Stage 1 parses manifests/lockfiles and builds dependency nodes in FalkorDB.
              </span>
              <button
                type="button"
                onClick={() => handleSelectTab('osv')}
                className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-4 py-2 font-medium text-white shadow-sm hover:bg-sky-400 transition"
              >
                <span>Continue to Stage 2: OSV Advisories</span>
                <ArrowRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {activeTab === 'osv' && (
          <div className="space-y-4">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-amber-400" />
              <span>Stage 2: OSV Advisory Ingestion &amp; Caching</span>
            </div>
            <OsvAdvisoryCard project={activeProject} />

            {/* Stage Navigation Footer */}
            <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-[#0f1822] p-4 text-xs">
              <button
                type="button"
                onClick={() => handleSelectTab('lockfile')}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3.5 py-2 font-medium text-slate-300 hover:bg-slate-700 hover:text-white transition"
              >
                <ArrowLeft className="h-4 w-4" />
                <span>Back to Stage 1: Lockfile</span>
              </button>
              <button
                type="button"
                onClick={() => handleSelectTab('matching')}
                className="inline-flex items-center gap-1.5 rounded-lg bg-amber-500 px-4 py-2 font-semibold text-slate-950 shadow-sm hover:bg-amber-400 transition"
              >
                <span>Continue to Stage 3: Version Matching</span>
                <ArrowRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {activeTab === 'matching' && (
          <div className="space-y-4">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Cpu className="h-4 w-4 text-emerald-400" />
              <span>Stage 3: Ecosystem-Aware Version Matching</span>
            </div>
            <VersionMatchingCard project={activeProject} />

            {/* Stage Navigation Footer */}
            <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-[#0f1822] p-4 text-xs">
              <button
                type="button"
                onClick={() => handleSelectTab('osv')}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3.5 py-2 font-medium text-slate-300 hover:bg-slate-700 hover:text-white transition"
              >
                <ArrowLeft className="h-4 w-4" />
                <span>Back to Stage 2: OSV Advisories</span>
              </button>
              <Link
                to="/findings"
                className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-4 py-2 font-semibold text-slate-950 shadow-sm hover:bg-emerald-400 transition"
              >
                <span>View Findings &amp; Exposure Paths</span>
                <ChevronRight className="h-4 w-4" />
              </Link>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
