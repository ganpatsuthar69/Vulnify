import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Cpu,
  FolderGit2,
  Layers,
  Loader2,
  Package,
  Plus,
  RefreshCw,
  Route,
  ShieldAlert,
  ShieldCheck,
  UploadCloud,
} from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router'
import {
  getProjectAdvisories,
  getProjectPackages,
  getProjectVulnerabilities,
} from '@/features/projects/projectApi'
import { useProjects } from '@/features/projects/ProjectProvider'
import type {
  PackageVersion,
  ProjectAdvisory,
  VulnerabilityFinding,
} from '@/features/projects/types'
import { CreateProjectModal } from '@/features/projects/CreateProjectModal'

export function DashboardPage() {
  const { activeProject, activeProjectId, projects, isLoading: isProjectsLoading } = useProjects()

  const [packages, setPackages] = useState<PackageVersion[]>([])
  const [advisories, setAdvisories] = useState<ProjectAdvisory[]>([])
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([])
  const [isLoadingData, setIsLoadingData] = useState(false)
  const [dataError, setDataError] = useState<string | null>(null)
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false)

  const loadDashboardData = useCallback(async (projectId: string) => {
    setIsLoadingData(true)
    setDataError(null)

    try {
      const [pkgs, advs, finds] = await Promise.all([
        getProjectPackages(projectId).catch(() => []),
        getProjectAdvisories(projectId).catch(() => []),
        getProjectVulnerabilities(projectId).catch(() => []),
      ])

      setPackages(pkgs)
      setAdvisories(advs)
      setFindings(finds)
    } catch {
      setDataError('Failed to load project metrics from FalkorDB.')
    } finally {
      setIsLoadingData(false)
    }
  }, [])

  useEffect(() => {
    if (activeProjectId) {
      void loadDashboardData(activeProjectId)
    } else {
      setPackages([])
      setAdvisories([])
      setFindings([])
    }
  }, [activeProjectId, loadDashboardData])

  // Count severities
  const criticalCount = findings.filter((f) => f.severity.toUpperCase() === 'CRITICAL').length
  const highCount = findings.filter((f) => f.severity.toUpperCase() === 'HIGH').length

  // Loading project state
  if (isProjectsLoading) {
    return (
      <div className="flex flex-col items-center justify-center rounded-xl border border-slate-800 bg-[#0f1822] p-16 text-slate-400">
        <Loader2 className="h-8 w-8 animate-spin text-sky-400" aria-hidden="true" />
        <span className="mt-4 text-sm font-medium text-slate-300">
          Connecting to FalkorDB graph...
        </span>
      </div>
    )
  }

  // Zero projects empty state
  if (projects.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 bg-[#0f1822] p-16 text-center">
        <div className="flex h-16 w-16 items-center justify-center rounded-full bg-slate-800/80 ring-1 ring-slate-700">
          <FolderGit2 className="h-8 w-8 text-sky-400" aria-hidden="true" />
        </div>
        <h2 className="mt-4 text-lg font-bold text-white">Welcome to Vulnify</h2>
        <p className="mt-2 max-w-md text-xs text-slate-400 leading-relaxed">
          Graph-powered security investigation workspace. Start by creating a project to import your
          service lockfiles, track dependency chains, and evaluate ecosystem-aware advisories.
        </p>
        <button
          type="button"
          onClick={() => setIsCreateModalOpen(true)}
          className="mt-6 inline-flex items-center gap-2 rounded-lg bg-sky-500 px-4 py-2.5 text-xs font-semibold text-white shadow-lg shadow-sky-500/20 hover:bg-sky-400 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
        >
          <Plus className="h-4 w-4" aria-hidden="true" />
          <span>Create First Project</span>
        </button>
        <CreateProjectModal
          isOpen={isCreateModalOpen}
          onClose={() => setIsCreateModalOpen(false)}
        />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Active Project Banner */}
      {activeProject && (
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-xl border border-sky-500/30 bg-sky-500/5 p-5">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="rounded-full bg-sky-500/20 px-2 py-0.5 text-[10px] font-bold text-sky-300 tracking-wide uppercase">
                Active Project
              </span>
              <h1 className="text-xl font-bold text-white">{activeProject.name}</h1>
              <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-semibold text-slate-300 uppercase">
                {activeProject.ecosystem}
              </span>
            </div>
            {activeProject.description && (
              <p className="mt-1 text-xs text-slate-300 max-w-2xl">{activeProject.description}</p>
            )}
          </div>

          <div className="flex items-center gap-2.5">
            <Link
              to="/import"
              className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-2 text-xs font-semibold text-white shadow-sm hover:bg-sky-400 transition-colors"
            >
              <UploadCloud className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Import Data</span>
            </Link>
            <button
              type="button"
              onClick={() => activeProjectId && void loadDashboardData(activeProjectId)}
              disabled={isLoadingData}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-700 hover:text-white transition-colors disabled:opacity-50"
              title="Refresh project metrics"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${isLoadingData ? 'animate-spin text-sky-400' : ''}`}
                aria-hidden="true"
              />
              <span className="hidden sm:inline">Refresh</span>
            </button>
          </div>
        </div>
      )}

      {/* Error Notice */}
      {dataError && (
        <div
          role="alert"
          className="flex items-center justify-between rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-200"
        >
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-rose-400 shrink-0" aria-hidden="true" />
            <span>{dataError}</span>
          </div>
          <button
            type="button"
            onClick={() => activeProjectId && void loadDashboardData(activeProjectId)}
            className="rounded bg-rose-500/20 px-2.5 py-1 font-semibold text-rose-200 hover:bg-rose-500/30"
          >
            Retry
          </button>
        </div>
      )}

      {/* Pipeline Data Freshness / Incomplete Ingestion Banner */}
      {activeProject && (
        <>
          {packages.length === 0 ? (
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-200">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
                <div className="flex-1">
                  <h2 className="text-xs font-bold text-white">
                    Step 1 Required: No dependencies imported yet
                  </h2>
                  <p className="mt-1 text-slate-300">
                    Upload your service's lockfile or dependency manifest to build
                    the dependency graph in FalkorDB before scanning for advisories.
                  </p>
                  <Link
                    to="/import"
                    className="mt-3 inline-flex items-center gap-1.5 rounded-md bg-amber-500/20 border border-amber-500/40 px-3 py-1.5 text-xs font-semibold text-amber-200 hover:bg-amber-500/30 transition-colors"
                  >
                    <span>Import dependencies now</span>
                    <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                  </Link>
                </div>
              </div>
            </div>
          ) : advisories.length === 0 ? (
            <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-4 text-xs text-sky-200">
              <div className="flex items-start gap-3">
                <Cpu className="h-5 w-5 text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />
                <div className="flex-1">
                  <h2 className="text-xs font-bold text-white">
                    Step 2 Required: {packages.length} package versions imported, advisories pending
                  </h2>
                  <p className="mt-1 text-slate-300">
                    Query the official OSV database for known vulnerabilities targeting your imported
                    dependencies.
                  </p>
                  <Link
                    to="/import"
                    className="mt-3 inline-flex items-center gap-1.5 rounded-md bg-sky-500/20 border border-sky-500/40 px-3 py-1.5 text-xs font-semibold text-sky-200 hover:bg-sky-500/30 transition-colors"
                  >
                    <span>Scan OSV advisories</span>
                    <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                  </Link>
                </div>
              </div>
            </div>
          ) : findings.length === 0 ? (
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-200">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
                <div className="flex-1">
                  <h2 className="text-xs font-bold text-white">
                    Step 3 Required: {advisories.length} advisories retrieved, version matching pending
                  </h2>
                  <p className="mt-1 text-slate-300">
                    Run ecosystem-aware version comparison to determine which advisories actually affect
                    your installed versions.
                  </p>
                  <Link
                    to="/import"
                    className="mt-3 inline-flex items-center gap-1.5 rounded-md bg-amber-500/20 border border-amber-500/40 px-3 py-1.5 text-xs font-semibold text-amber-200 hover:bg-amber-500/30 transition-colors"
                  >
                    <span>Run version matching</span>
                    <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                  </Link>
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-xs text-emerald-200">
              <div className="flex items-center gap-3">
                <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" aria-hidden="true" />
                <div>
                  <span className="font-semibold text-white">Security Pipeline Active: </span>
                  <span>
                    Dependencies, OSV advisories, and version matching results are verified and up to
                    date in FalkorDB.
                  </span>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* 4 Data-Driven Summary Cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {/* Card 1: Package Versions */}
        <Link
          to="/dependencies"
          className="group rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl transition-all hover:border-slate-700 hover:bg-slate-900/60"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Imported Packages</span>
            <Package className="h-4 w-4 text-sky-400" aria-hidden="true" />
          </div>
          <div className="mt-3 text-3xl font-bold text-white">
            {isLoadingData ? (
              <Loader2 className="h-7 w-7 animate-spin text-slate-500" />
            ) : (
              packages.length
            )}
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Graph nodes in FalkorDB</span>
            <span className="text-sky-400 group-hover:translate-x-0.5 transition-transform">&rarr;</span>
          </div>
        </Link>

        {/* Card 2: Advisory Matches */}
        <Link
          to="/import"
          className="group rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl transition-all hover:border-slate-700 hover:bg-slate-900/60"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Advisory Matches</span>
            <ShieldCheck className="h-4 w-4 text-amber-400" aria-hidden="true" />
          </div>
          <div className="mt-3 text-3xl font-bold text-amber-400">
            {isLoadingData ? (
              <Loader2 className="h-7 w-7 animate-spin text-slate-500" />
            ) : (
              advisories.length
            )}
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center justify-between">
            <span>OSV upstream records</span>
            <span className="text-sky-400 group-hover:translate-x-0.5 transition-transform">&rarr;</span>
          </div>
        </Link>

        {/* Card 3: Confirmed Findings */}
        <Link
          to="/findings"
          className="group rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl transition-all hover:border-slate-700 hover:bg-slate-900/60"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Affected Findings</span>
            <ShieldAlert className="h-4 w-4 text-rose-400" aria-hidden="true" />
          </div>
          <div className="mt-3 text-3xl font-bold text-rose-400">
            {isLoadingData ? (
              <Loader2 className="h-7 w-7 animate-spin text-slate-500" />
            ) : (
              findings.length
            )}
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Ecosystem version confirmed</span>
            <span className="text-sky-400 group-hover:translate-x-0.5 transition-transform">&rarr;</span>
          </div>
        </Link>

        {/* Card 4: Critical & High Priority */}
        <Link
          to="/priorities"
          className="group rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl transition-all hover:border-slate-700 hover:bg-slate-900/60"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider">Critical / High</span>
            <Layers className="h-4 w-4 text-red-500" aria-hidden="true" />
          </div>
          <div className="mt-3 text-3xl font-bold text-white">
            {isLoadingData ? (
              <Loader2 className="h-7 w-7 animate-spin text-slate-500" />
            ) : (
              <span>
                <span className="text-red-400">{criticalCount}</span>
                <span className="text-slate-500 mx-1">/</span>
                <span className="text-orange-400">{highCount}</span>
              </span>
            )}
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Deterministic ranking</span>
            <span className="text-sky-400 group-hover:translate-x-0.5 transition-transform">&rarr;</span>
          </div>
        </Link>
      </div>

      {/* Quick Navigation Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Link
          to="/findings"
          className="group flex flex-col justify-between rounded-xl border border-slate-800 bg-[#0f1822] p-5 transition-all hover:border-slate-700 hover:bg-slate-900/60"
        >
          <div>
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-rose-500/10 text-rose-400 ring-1 ring-rose-500/20">
                <ShieldAlert className="h-4 w-4" />
              </div>
              <h3 className="text-sm font-bold text-white">Review Findings</h3>
            </div>
            <p className="mt-2.5 text-xs text-slate-400 leading-relaxed">
              Browse confirmed affected packages, CVSS severity ratings, and fixed versions with
              explainable version match evidence.
            </p>
          </div>
          <div className="mt-4 flex items-center gap-1.5 text-xs font-semibold text-sky-400 group-hover:text-sky-300">
            <span>View all findings</span>
            <ArrowRight className="h-3.5 w-3.5 group-hover:translate-x-0.5 transition-transform" />
          </div>
        </Link>

        <Link
          to="/graph"
          className="group flex flex-col justify-between rounded-xl border border-slate-800 bg-[#0f1822] p-5 transition-all hover:border-slate-700 hover:bg-slate-900/60"
        >
          <div>
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-500/10 text-sky-400 ring-1 ring-sky-500/20">
                <Route className="h-4 w-4" />
              </div>
              <h3 className="text-sm font-bold text-white">Dependency Graph</h3>
            </div>
            <p className="mt-2.5 text-xs text-slate-400 leading-relaxed">
              Explore interconnected dependency relationships and trace how packages are reached from
              service manifests in FalkorDB.
            </p>
          </div>
          <div className="mt-4 flex items-center gap-1.5 text-xs font-semibold text-sky-400 group-hover:text-sky-300">
            <span>Inspect graph</span>
            <ArrowRight className="h-3.5 w-3.5 group-hover:translate-x-0.5 transition-transform" />
          </div>
        </Link>

        <Link
          to="/investigation"
          className="group flex flex-col justify-between rounded-xl border border-slate-800 bg-[#0f1822] p-5 transition-all hover:border-slate-700 hover:bg-slate-900/60"
        >
          <div>
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500/10 text-indigo-400 ring-1 ring-indigo-500/20">
                <Cpu className="h-4 w-4" />
              </div>
              <h3 className="text-sm font-bold text-white">AI Security Agent</h3>
            </div>
            <p className="mt-2.5 text-xs text-slate-400 leading-relaxed">
              Ask natural language security questions grounded in your project graph with verified tool
              call transparency.
            </p>
          </div>
          <div className="mt-4 flex items-center gap-1.5 text-xs font-semibold text-sky-400 group-hover:text-sky-300">
            <span>Launch investigation</span>
            <ArrowRight className="h-3.5 w-3.5 group-hover:translate-x-0.5 transition-transform" />
          </div>
        </Link>
      </div>

      {/* Top Vulnerability Findings Table Preview */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div>
            <h3 className="text-sm font-bold text-white">Top Confirmed Findings</h3>
            <p className="text-xs text-slate-400">
              Vulnerabilities confirmed by ecosystem-aware version evaluation
            </p>
          </div>
          <Link
            to="/findings"
            className="text-xs font-semibold text-sky-400 hover:text-sky-300 transition-colors"
          >
            View all ({findings.length}) &rarr;
          </Link>
        </div>

        {findings.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-500">
            {packages.length === 0
              ? 'No packages imported. Upload a lockfile in Import Data to see findings.'
              : advisories.length === 0
              ? 'Advisories not yet scanned. Run OSV advisory ingestion to detect vulnerabilities.'
              : 'Zero affected vulnerability findings detected for current installed versions.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 px-3 font-semibold">Severity</th>
                  <th className="py-2.5 px-3 font-semibold">Advisory</th>
                  <th className="py-2.5 px-3 font-semibold">Package &amp; Version</th>
                  <th className="py-2.5 px-3 font-semibold">Match Reason</th>
                  <th className="py-2.5 px-3 font-semibold">Fixed In</th>
                  <th className="py-2.5 px-3 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {findings.slice(0, 5).map((f) => (
                  <tr key={`${f.id}-${f.package_version_id}`} className="hover:bg-slate-900/40">
                    <td className="py-3 px-3">
                      <span
                        className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                          f.severity.toUpperCase() === 'CRITICAL'
                            ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                            : f.severity.toUpperCase() === 'HIGH'
                            ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30'
                            : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                        }`}
                      >
                        {f.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono font-semibold text-slate-200">{f.id}</td>
                    <td className="py-3 px-3">
                      <span className="font-semibold text-white">{f.package_name}</span>
                      <span className="text-slate-400 ml-1.5 font-mono">@{f.package_version}</span>
                    </td>
                    <td className="py-3 px-3 text-slate-400 max-w-xs truncate" title={f.match_reason}>
                      {f.match_reason}
                    </td>
                    <td className="py-3 px-3 font-mono text-emerald-400 font-semibold">
                      {f.fixed_version ? `>= ${f.fixed_version}` : 'None'}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <Link
                        to={`/findings/${f.id}`}
                        className="rounded bg-slate-800 px-2.5 py-1 text-slate-300 hover:bg-slate-700 hover:text-white font-semibold transition-colors"
                      >
                        Detail
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
