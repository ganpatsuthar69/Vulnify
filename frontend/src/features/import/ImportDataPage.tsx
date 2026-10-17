import { useState } from 'react'
import {
  UploadCloud,
  ShieldAlert,
  Cpu,
  AlertCircle,
} from 'lucide-react'
import { useProjects } from '@/features/projects/ProjectProvider'
import { LockfileImportCard } from '@/features/dependencies/LockfileImportCard'
import { OsvAdvisoryCard } from '@/features/advisories/OsvAdvisoryCard'
import { VersionMatchingCard } from '@/features/advisories/VersionMatchingCard'

export function ImportDataPage() {
  const { activeProject } = useProjects()
  const [activeTab, setActiveTab] = useState<'all' | 'lockfile' | 'osv' | 'matching'>('all')

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
            onClick={() => setActiveTab('all')}
            className={`rounded-md px-3 py-1 font-medium transition-colors ${
              activeTab === 'all'
                ? 'bg-sky-500 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All Stages
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('lockfile')}
            className={`rounded-md px-3 py-1 font-medium transition-colors ${
              activeTab === 'lockfile'
                ? 'bg-sky-500 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            1. Lockfile
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('osv')}
            className={`rounded-md px-3 py-1 font-medium transition-colors ${
              activeTab === 'osv'
                ? 'bg-sky-500 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            2. OSV Advisories
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('matching')}
            className={`rounded-md px-3 py-1 font-medium transition-colors ${
              activeTab === 'matching'
                ? 'bg-sky-500 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            3. Version Matching
          </button>
        </div>
      </div>

      {/* Stage Progression Breadcrumb Guide */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-[#0f1822] p-3 text-xs">
          <div className="flex h-7 w-7 items-center justify-center rounded bg-sky-500/15 text-sky-400 font-bold shrink-0">
            1
          </div>
          <div>
            <div className="font-semibold text-white">Parse &amp; Persist Graph</div>
            <div className="text-[11px] text-slate-400">Upload lockfile / manifest (US-102)</div>
          </div>
        </div>

        <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-[#0f1822] p-3 text-xs">
          <div className="flex h-7 w-7 items-center justify-center rounded bg-amber-500/15 text-amber-400 font-bold shrink-0">
            2
          </div>
          <div>
            <div className="font-semibold text-white">Ingest OSV Advisories</div>
            <div className="text-[11px] text-slate-400">Query api.osv.dev batch (US-103)</div>
          </div>
        </div>

        <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-[#0f1822] p-3 text-xs">
          <div className="flex h-7 w-7 items-center justify-center rounded bg-emerald-500/15 text-emerald-400 font-bold shrink-0">
            3
          </div>
          <div>
            <div className="font-semibold text-white">Ecosystem Matching</div>
            <div className="text-[11px] text-slate-400">Evaluate SemVer ranges (US-104)</div>
          </div>
        </div>
      </div>

      {/* Ingestion Cards */}
      <div className="space-y-6">
        {(activeTab === 'all' || activeTab === 'lockfile') && (
          <div className="space-y-2">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <UploadCloud className="h-4 w-4 text-sky-400" />
              <span>Stage 1: Multi-Ecosystem Dependency Ingestion (US-102)</span>
            </div>
            <LockfileImportCard project={activeProject} />
          </div>
        )}

        {(activeTab === 'all' || activeTab === 'osv') && (
          <div className="space-y-2">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-amber-400" />
              <span>Stage 2: OSV Advisory Ingestion &amp; Caching (US-103)</span>
            </div>
            <OsvAdvisoryCard project={activeProject} />
          </div>
        )}

        {(activeTab === 'all' || activeTab === 'matching') && (
          <div className="space-y-2">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Cpu className="h-4 w-4 text-emerald-400" />
              <span>Stage 3: Ecosystem-Aware Version Matching (US-104)</span>
            </div>
            <VersionMatchingCard project={activeProject} />
          </div>
        )}
      </div>
    </div>
  )
}
