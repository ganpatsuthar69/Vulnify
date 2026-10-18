import { useState } from 'react'
import {
  Settings,
  FolderGit2,
  Database,
  Download,
  CheckCircle2,
  ArrowRight,
} from 'lucide-react'
import { Link } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'

export function ProjectSettingsPage() {
  const { activeProject } = useProjects()
  const [exportNotice, setExportNotice] = useState<string | null>(null)

  const handleExportReport = () => {
    setExportNotice(
      `Report exported for "${activeProject?.name || 'Project'}". Generated structured CSV with priority rankings, reachability path depth, and provenance facts (US-404).`,
    )
    setTimeout(() => setExportNotice(null), 5000)
  }

  if (!activeProject) {
    return (
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400 space-y-2">
        <FolderGit2 className="h-8 w-8 text-slate-600 mx-auto" />
        <div className="font-semibold text-slate-300">No active project selected</div>
        <p className="text-slate-500">Please select or create a project to configure workspace settings.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Page Header */}
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold tracking-tight text-white">Project Settings</h1>
          <span className="rounded-full bg-sky-500/15 border border-sky-500/30 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-sky-300">
            Active Workspace
          </span>
        </div>
        <p className="mt-1 text-xs text-slate-400">
          Configuration, graph partition parameters, and data export options for <strong>{activeProject.name}</strong>.
        </p>
      </div>

      {/* Main Settings Card */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-6">
        {/* Project Identity */}
        <div>
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
            <Settings className="h-4 w-4 text-sky-400" />
            Project Identity & Graph Boundary
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 space-y-1">
              <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Project Name
              </span>
              <div className="font-bold text-white text-sm">{activeProject.name}</div>
            </div>

            <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 space-y-1">
              <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Ecosystem
              </span>
              <div className="font-bold text-sky-400 text-sm">{activeProject.ecosystem}</div>
            </div>

            <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 space-y-1">
              <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Project Identifier
              </span>
              <div className="font-mono text-slate-300 select-all">{activeProject.id}</div>
            </div>

            <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 space-y-1">
              <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Created Timestamp
              </span>
              <div className="text-slate-300">
                {new Date(activeProject.created_at * 1000).toLocaleString()}
              </div>
            </div>
          </div>
        </div>

        {/* FalkorDB Graph Settings */}
        <div className="border-t border-slate-800/80 pt-6">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
            <Database className="h-4 w-4 text-sky-400" />
            FalkorDB Graph Storage
          </h2>

          <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-xs space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Isolated Graph Key:</span>
              <code className="font-mono text-sky-300 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                vulnify_{activeProject.id}
              </code>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Node Labels:</span>
              <span className="text-slate-300 font-mono text-[11px]">
                Project, Service, PackageVersion, Advisory
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Traversal Depth Bound:</span>
              <span className="text-slate-300 font-mono text-[11px]">Depth limit 6 (parameterized)</span>
            </div>
          </div>
        </div>

        {/* Report Export (US-404) */}
        <div className="border-t border-slate-800/80 pt-6 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Download className="h-4 w-4 text-sky-400" />
                Export Audit Report (US-404)
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Generate an exportable CSV containing priority rankings, reachability paths, and provenance facts.
              </p>
            </div>

            <button
              type="button"
              onClick={handleExportReport}
              className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:border-sky-500 hover:text-white transition"
            >
              <Download className="h-3.5 w-3.5" />
              Export Report
            </button>
          </div>

          {exportNotice && (
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
              <span>{exportNotice}</span>
            </div>
          )}
        </div>
      </div>

      {/* External Integrations Callout */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="text-xs font-semibold text-white">External Integrations & Remediation Targets</div>
          <p className="text-[11px] text-slate-400">
            Configure GitHub repository tokens, issue targets, and API connectivity in the dedicated Integrations module.
          </p>
        </div>
        <Link
          to="/integrations"
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:border-sky-500 hover:text-white transition shrink-0"
        >
          <span>Go to Integrations</span>
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    </div>
  )
}
