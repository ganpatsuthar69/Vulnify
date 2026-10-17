import { useState, useEffect } from 'react'
import {
  Route,
  AlertTriangle,
  Layers,
  ShieldAlert,
  ArrowRight,
  Package,
  Loader2,
  Info,
} from 'lucide-react'
import { Link } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import { getProjectVulnerabilities } from '@/features/projects/projectApi'
import type { VulnerabilityFinding } from '@/features/projects/types'

export function ExposurePathsPage() {
  const { activeProject } = useProjects()
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([])
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

  if (!activeProject) {
    return (
      <div className="rounded-xl border border-dashed border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
        <h2 className="text-sm font-bold text-white">No Active Project Selected</h2>
        <p className="mt-1">Please select an active project to analyze exposure paths.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-white">Exposure Paths &amp; Reachability</h1>
            <span className="rounded-full bg-sky-500/20 border border-sky-500/30 px-2.5 py-0.5 text-xs font-semibold text-sky-300">
              US-204 &bull; Architectural Analysis
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Traces how vulnerable packages are reached through dependency chains from services in{' '}
            <span className="font-semibold text-slate-200">{activeProject.name}</span>.
          </p>
        </div>
      </div>

      {/* Mandatory Honesty & Safety Alert Banner */}
      <div
        role="alert"
        className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-5 text-xs text-amber-200 leading-relaxed space-y-1.5"
      >
        <div className="flex items-center gap-2 font-bold text-amber-300">
          <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />
          <span>Architectural Exposure, Not Proof of Exploitability</span>
        </div>
        <p className="text-amber-200/90">
          Paths show architectural exposure, demonstrating that a package version is present in your build
          or service graph. <strong>"No path found" is not a guarantee of safety</strong>. Path reachability
          identifies where the dependency tree links code together, not runtime exploit execution.
        </p>
      </div>

      {/* Exposure Chains List */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Route className="h-4 w-4 text-sky-400" />
            <span>Active Exposure Chains ({findings.length})</span>
          </h2>
        </div>

        {isLoading ? (
          <div className="flex flex-col items-center justify-center rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-slate-400">
            <Loader2 className="h-8 w-8 animate-spin text-sky-400" />
            <span className="mt-3 text-xs">Tracing dependency paths in FalkorDB...</span>
          </div>
        ) : findings.length === 0 ? (
          <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
            <Info className="mx-auto h-8 w-8 text-slate-500 mb-2" />
            <h3 className="font-semibold text-white">No active vulnerability paths</h3>
            <p className="mt-1 text-slate-500">
              There are no confirmed affected vulnerability relationships currently attached to
              services in this project.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {findings.map((f) => (
              <div
                key={`${f.id}-${f.package_version_id}`}
                className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-4"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                  <div className="flex items-center gap-3">
                    <span
                      className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border ${
                        f.severity.toUpperCase() === 'CRITICAL'
                          ? 'border-red-500/40 bg-red-500/15 text-red-300'
                          : f.severity.toUpperCase() === 'HIGH'
                          ? 'border-orange-500/40 bg-orange-500/15 text-orange-300'
                          : 'border-amber-500/40 bg-amber-500/15 text-amber-300'
                      }`}
                    >
                      {f.severity}
                    </span>
                    <span className="font-mono font-bold text-white text-sm">{f.id}</span>
                    <span className="text-xs text-slate-400 truncate max-w-md">{f.summary}</span>
                  </div>

                  <Link
                    to={`/findings/${f.id}`}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-sky-400 hover:text-sky-300 shrink-0"
                  >
                    <span>View Detail</span>
                    <ArrowRight className="h-3 w-3" />
                  </Link>
                </div>

                {/* Path Visual Representation */}
                <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4">
                  <div className="flex flex-col md:flex-row items-center justify-between gap-3 text-xs font-mono">
                    {/* Node 1: Service */}
                    <div className="flex items-center gap-2 rounded bg-slate-800/80 px-3 py-2 text-slate-200 w-full md:w-auto justify-center">
                      <Layers className="h-4 w-4 text-sky-400 shrink-0" />
                      <span>{activeProject.name} (Service)</span>
                    </div>

                    <div className="text-slate-500 text-[11px] font-sans flex items-center gap-1">
                      <span>&rarr;</span>
                      <span className="rounded bg-slate-900 px-1.5 py-0.5 text-[10px] text-slate-400">
                        DEPENDS_ON*
                      </span>
                      <span>&rarr;</span>
                    </div>

                    {/* Node 2: Package Version */}
                    <div className="flex items-center gap-2 rounded border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-sky-300 w-full md:w-auto justify-center">
                      <Package className="h-4 w-4 shrink-0" />
                      <span>
                        {f.package_name}@{f.package_version}
                      </span>
                    </div>

                    <div className="text-slate-500 text-[11px] font-sans flex items-center gap-1">
                      <span>&rarr;</span>
                      <span className="rounded bg-slate-900 px-1.5 py-0.5 text-[10px] text-rose-400">
                        AFFECTS
                      </span>
                      <span>&rarr;</span>
                    </div>

                    {/* Node 3: Vulnerability */}
                    <div className="flex items-center gap-2 rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-rose-300 w-full md:w-auto justify-center">
                      <ShieldAlert className="h-4 w-4 shrink-0" />
                      <span>{f.id}</span>
                    </div>
                  </div>

                  <div className="mt-3 pt-3 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] text-slate-400">
                    <div>
                      <strong>Evaluated Rule:</strong> {f.match_reason}
                    </div>
                    <div>
                      <strong>Remediation Target:</strong>{' '}
                      <span className="font-mono text-emerald-400">
                        {f.fixed_version ? `>= ${f.fixed_version}` : 'No fix specified'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
