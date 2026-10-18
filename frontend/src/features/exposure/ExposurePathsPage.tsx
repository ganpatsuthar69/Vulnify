import { useState, useEffect, useCallback } from 'react'
import {
  Route,
  AlertTriangle,
  Globe,
  ArrowRight,
  Package,
  Loader2,
  Info,
  ShieldAlert,
  Server,
  Network,
  RefreshCw,
  HelpCircle,
} from 'lucide-react'
import { Link } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import { getProjectExposurePaths, ProjectApiError } from '@/features/projects/projectApi'
import type { ProjectExposurePathsResponse } from '@/features/projects/types'

export function ExposurePathsPage() {
  const { activeProject } = useProjects()
  const [data, setData] = useState<ProjectExposurePathsResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadData = useCallback(async () => {
    if (!activeProject) return
    setIsLoading(true)
    setError(null)
    try {
      const resp = await getProjectExposurePaths(activeProject.id)
      setData(resp)
    } catch (err: unknown) {
      if (err instanceof ProjectApiError) {
        setError(err.message)
      } else {
        setError('Failed to fetch architectural exposure paths from graph database.')
      }
    } finally {
      setIsLoading(false)
    }
  }, [activeProject])

  useEffect(() => {
    void loadData()
  }, [loadData])

  if (!activeProject) {
    return (
      <div className="rounded-xl border border-dashed border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
        <h2 className="text-sm font-bold text-white">No Active Project Selected</h2>
        <p className="mt-1">Please select an active project to analyze architectural exposure paths.</p>
      </div>
    )
  }

  const items = data?.items ?? []
  const unsupportedEcosystems = data?.unsupported_ecosystems ?? []
  const isMissingTopology = data?.topology_status === 'missing_topology'

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-white">Exposure Paths &amp; Topology Traversal</h1>
            <span className="rounded-full bg-sky-500/20 border border-sky-500/30 px-2.5 py-0.5 text-xs font-semibold text-sky-300">
              US-205 &bull; Architectural Exposure (R2)
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Traverses FalkorDB graph topology to evaluate how internet-facing entrypoints reach vulnerable packages
            across service calls and dependency chains in{' '}
            <span className="font-semibold text-slate-200">{activeProject.name}</span>.
          </p>
        </div>

        <button
          type="button"
          onClick={() => void loadData()}
          disabled={isLoading}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50 self-start sm:self-auto"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin text-sky-400' : ''}`} />
          <span>Refresh Traversal</span>
        </button>
      </div>

      {/* Mandatory Honesty & Safety Alert Banner (US-205 AC2) */}
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
          identifies where the dependency tree and service topology link code together, not runtime exploit execution.
        </p>
      </div>

      {/* Missing Topology Notice (US-205 & US-207) */}
      {isMissingTopology && (
        <div className="rounded-xl border border-amber-500/30 bg-[#161208] p-4 text-xs text-amber-200 flex items-start gap-3">
          <Network className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-bold text-amber-300">Service-to-Service Topology Not Imported</div>
            <p className="mt-1 text-amber-200/80 leading-relaxed">
              No inter-service call edges (<code>CALLS</code>) were found in this project. Exposure paths below reflect
              internal service package dependencies only and cannot verify reachability from external ingress or across services.
            </p>
          </div>
        </div>
      )}

      {/* Unsupported Ecosystems Card (US-205 AC3) */}
      {unsupportedEcosystems.length > 0 && (
        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-3">
          <div className="flex items-center gap-2 text-sm font-bold text-white border-b border-slate-800 pb-2">
            <HelpCircle className="h-4 w-4 text-zinc-400" />
            <span>Unsupported Ecosystems &mdash; Listed as Not Analyzed (US-205 AC3)</span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            The following package dependencies belong to ecosystems not currently supported for automated SemVer
            matching in Vulnify. Per our honesty policy, these are classified as <strong>not analyzed</strong> rather than safe.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 pt-1">
            {unsupportedEcosystems.map((ue) => (
              <div
                key={`${ue.service_name}-${ue.package_name}@${ue.package_version}`}
                className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 text-xs space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-white">{ue.package_name}</span>
                  <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-mono text-zinc-400 uppercase">
                    {ue.ecosystem}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 font-mono">v{ue.package_version} &bull; Service: {ue.service_name}</div>
                <div className="text-[10px] text-amber-400/90 font-medium">{ue.reason}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Exposure Chains List */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Route className="h-4 w-4 text-sky-400" />
            <span>Architectural Exposure Chains ({items.length})</span>
          </h2>
        </div>

        {isLoading ? (
          <div className="flex flex-col items-center justify-center rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-slate-400">
            <Loader2 className="h-8 w-8 animate-spin text-sky-400" />
            <span className="mt-3 text-xs">Traversing service topology and dependency chains in FalkorDB...</span>
          </div>
        ) : error ? (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-6 text-xs text-red-200 space-y-2">
            <div className="font-bold text-red-300">Topology Traversal Query Failed</div>
            <p>{error}</p>
          </div>
        ) : items.length === 0 ? (
          <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
            <Info className="mx-auto h-8 w-8 text-slate-500 mb-2" />
            <h3 className="font-semibold text-white">No active vulnerability paths found</h3>
            <p className="mt-1 text-slate-500">
              There are no confirmed affected vulnerability relationships currently linked to
              services in this project.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {items.map((item) => (
              <div
                key={`${item.finding_id}-${item.package_version_id}`}
                className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-4"
              >
                {/* Header Row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                  <div className="flex flex-wrap items-center gap-2.5">
                    {/* Severity Badge */}
                    <span
                      className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border ${
                        item.severity.toUpperCase() === 'CRITICAL'
                          ? 'border-red-500/40 bg-red-500/15 text-red-300'
                          : item.severity.toUpperCase() === 'HIGH'
                          ? 'border-orange-500/40 bg-orange-500/15 text-orange-300'
                          : 'border-amber-500/40 bg-amber-500/15 text-amber-300'
                      }`}
                    >
                      {item.severity}
                    </span>

                    {/* Exposure Status Badge (US-205 AC1) */}
                    {item.exposure_status === 'internet_exposed' ? (
                      <span className="rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border border-rose-500/40 bg-rose-500/15 text-rose-300 flex items-center gap-1">
                        <Globe className="h-3 w-3" />
                        <span>Internet Reachable</span>
                      </span>
                    ) : item.exposure_status === 'missing_topology' ? (
                      <span className="rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border border-amber-500/40 bg-amber-500/15 text-amber-300">
                        Missing Topology
                      </span>
                    ) : (
                      <span className="rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border border-slate-700 bg-slate-800 text-slate-300">
                        Internal Only
                      </span>
                    )}

                    {/* Synthetic Edges Flag (US-205 AC3) */}
                    {item.has_synthetic_edges && (
                      <span className="rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border border-amber-500/40 bg-amber-500/10 text-amber-300 flex items-center gap-1">
                        <span>Synthetic Edge</span>
                      </span>
                    )}

                    <span className="font-mono font-bold text-white text-sm">{item.advisory_id}</span>
                    <span className="text-xs text-slate-400 truncate max-w-sm">
                      {item.package_name}@{item.package_version}
                    </span>
                  </div>

                  <Link
                    to={`/findings/${item.finding_id}`}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-sky-400 hover:text-sky-300 shrink-0"
                  >
                    <span>View Finding Detail</span>
                    <ArrowRight className="h-3 w-3" />
                  </Link>
                </div>

                {/* Path Visual Representation (US-205 AC1) */}
                {item.paths.map((p) => (
                  <div key={p.id} className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 space-y-3">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                      {p.nodes.map((node, idx) => {
                        const isInternet = node.is_internet || node.node_type === 'internet'
                        const isService = node.node_type === 'service'
                        const isTarget = node.is_target
                        const edgeToNext = p.edges[idx]

                        return (
                          <div key={node.id} className="flex items-center gap-2">
                            {/* Node Bubble */}
                            <div
                              className={`flex items-center gap-1.5 rounded px-2.5 py-1.5 border text-xs ${
                                isInternet
                                  ? 'border-rose-500/50 bg-rose-500/10 text-rose-300 font-bold'
                                  : isTarget
                                  ? 'border-red-500/50 bg-red-500/10 text-red-300 font-bold'
                                  : isService
                                  ? 'border-sky-500/40 bg-sky-500/10 text-sky-200'
                                  : 'border-slate-700 bg-slate-800 text-slate-300'
                              }`}
                            >
                              {isInternet ? (
                                <Globe className="h-3.5 w-3.5 text-rose-400 shrink-0" />
                              ) : isService ? (
                                <Server className="h-3.5 w-3.5 text-sky-400 shrink-0" />
                              ) : isTarget ? (
                                <ShieldAlert className="h-3.5 w-3.5 text-red-400 shrink-0" />
                              ) : (
                                <Package className="h-3.5 w-3.5 text-slate-400 shrink-0" />
                              )}
                              <span>{node.display_name}</span>
                              {node.internet_facing && !isInternet && (
                                <span className="rounded bg-sky-500/20 text-[9px] px-1 py-0.2 text-sky-300 font-sans font-semibold">
                                  ingress
                                </span>
                              )}
                            </div>

                            {/* Edge to next node */}
                            {edgeToNext && (
                              <div className="flex items-center gap-1 text-slate-500 font-sans text-[11px]">
                                <span>&rarr;</span>
                                <span
                                  className={`rounded px-1.5 py-0.5 text-[10px] font-mono border ${
                                    edgeToNext.is_synthetic
                                      ? 'bg-amber-500/15 border-amber-500/30 text-amber-300 font-bold'
                                      : 'bg-slate-900 border-slate-800 text-slate-400'
                                  }`}
                                  title={edgeToNext.is_synthetic ? 'Synthetic Edge (US-205 AC3)' : 'Verified Manifest Edge'}
                                >
                                  {edgeToNext.relationship_type}
                                  {edgeToNext.is_synthetic && ' (synthetic)'}
                                </span>
                                <span>&rarr;</span>
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>

                    {/* Accessible Screen-Reader Summary (AC1) */}
                    <div className="text-[11px] text-slate-400 font-sans border-t border-slate-800/80 pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="truncate max-w-3xl">
                        <span className="font-semibold text-slate-300">Path Evidence:</span> {p.summary_text}
                      </div>
                      <div className="font-mono text-[10px] text-slate-500 shrink-0">
                        Depth: {p.total_depth} hop(s) &bull; Service calls: {p.service_hop_count} &bull; Package hops: {p.package_hop_count}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
