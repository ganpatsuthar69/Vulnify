import { useState, useEffect, useMemo } from 'react'
import {
  Network,
  Package,
  ShieldAlert,
  Layers,
  Search,
  Loader2,
  AlertCircle,
  Eye,
  ExternalLink,
} from 'lucide-react'
import { Link } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import {
  getProjectPackages,
  getProjectVulnerabilities,
} from '@/features/projects/projectApi'
import type {
  PackageVersion,
  VulnerabilityFinding,
} from '@/features/projects/types'

export function DependencyGraphPage() {
  const { activeProject } = useProjects()

  const [packages, setPackages] = useState<PackageVersion[]>([])
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([])
  const [selectedNode, setSelectedNode] = useState<{
    type: 'service' | 'package' | 'vulnerability'
    id: string
    name: string
    meta?: any
  } | null>(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function loadGraphData() {
      if (!activeProject) return
      setIsLoading(true)
      setError(null)
      try {
        const [pkgs, finds] = await Promise.all([
          getProjectPackages(activeProject.id),
          getProjectVulnerabilities(activeProject.id),
        ])
        setPackages(pkgs)
        setFindings(finds)
      } catch {
        setError('Failed to load dependency graph from FalkorDB.')
      } finally {
        setIsLoading(false)
      }
    }

    void loadGraphData()
  }, [activeProject])

  const vulnerablePkgNames = useMemo(() => {
    return new Set(findings.map((f) => f.package_name))
  }, [findings])

  const filteredPackages = useMemo(() => {
    return packages.filter((p) =>
      p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.version.toLowerCase().includes(searchTerm.toLowerCase()),
    )
  }, [packages, searchTerm])

  if (!activeProject) {
    return (
      <div className="rounded-xl border border-dashed border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
        <AlertCircle className="mx-auto h-8 w-8 text-amber-400" aria-hidden="true" />
        <h2 className="mt-3 text-sm font-bold text-white">No Active Project Selected</h2>
        <p className="mt-1 text-slate-400">
          Please select or create a project in the top navigation bar to view its dependency graph.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-white">Dependency Graph Explorer</h1>
            <span className="rounded-full bg-sky-500/20 border border-sky-500/30 px-2.5 py-0.5 text-xs font-semibold text-sky-300">
              {packages.length} Nodes &bull; {findings.length} Vulnerabilities
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Interactive representation of FalkorDB graph relationships for{' '}
            <span className="font-semibold text-slate-200">{activeProject.name}</span>.
          </p>
        </div>

        <div className="flex items-center gap-2.5 text-xs text-slate-400">
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-rose-500" />
            <span>Affected Package</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-sky-400" />
            <span>Clean Package</span>
          </span>
        </div>
      </div>

      {/* Main Explorer Region */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left Column: Interactive Graph Map */}
        <div className="lg:col-span-2 space-y-4">
          {/* Search Bar */}
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" aria-hidden="true" />
            <input
              type="search"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search graph nodes by package name..."
              className="w-full rounded-lg border border-slate-700 bg-[#0f1822] py-2 pl-9 pr-3 text-xs text-slate-200 placeholder-slate-500 transition-colors focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
          </div>

          {/* Graph Visual Canvas / Cards */}
          <div className="rounded-xl border border-slate-800 bg-[#0b121a] p-6 min-h-[420px] shadow-inner relative overflow-hidden">
            {isLoading ? (
              <div className="flex flex-col items-center justify-center p-16 text-slate-400">
                <Loader2 className="h-8 w-8 animate-spin text-sky-400" aria-hidden="true" />
                <span className="mt-3 text-xs font-medium text-slate-300">
                  Rendering FalkorDB relationships...
                </span>
              </div>
            ) : error ? (
              <div className="flex flex-col items-center justify-center p-16 text-center text-xs text-red-400">
                <AlertCircle className="h-8 w-8 text-red-400 mb-2" />
                <span>{error}</span>
              </div>
            ) : packages.length === 0 ? (
              <div className="flex flex-col items-center justify-center p-16 text-center text-xs text-slate-400">
                <Network className="h-10 w-10 text-slate-600 mb-3" />
                <h3 className="font-semibold text-white">No Graph Nodes Stored</h3>
                <p className="mt-1 text-slate-500 max-w-sm">
                  Upload a lockfile in the Import Data page to populate nodes and edges in FalkorDB.
                </p>
                <Link
                  to="/import"
                  className="mt-4 rounded-lg bg-sky-500 px-3.5 py-1.5 font-semibold text-white hover:bg-sky-400 transition-colors"
                >
                  Import Data
                </Link>
              </div>
            ) : (
              <div className="space-y-6">
                {/* Root Service Node */}
                <div className="flex justify-center">
                  <button
                    type="button"
                    onClick={() =>
                      setSelectedNode({
                        type: 'service',
                        id: activeProject.id,
                        name: `${activeProject.name} Service`,
                        meta: { ecosystem: activeProject.ecosystem },
                      })
                    }
                    className="flex items-center gap-2.5 rounded-xl border border-sky-500/40 bg-sky-500/10 px-5 py-2.5 text-xs font-bold text-white shadow-lg shadow-sky-500/5 hover:border-sky-400 hover:bg-sky-500/20 transition-all focus:outline-none focus:ring-2 focus:ring-sky-400"
                  >
                    <Layers className="h-4 w-4 text-sky-400" />
                    <span>Project Service: {activeProject.name}</span>
                  </button>
                </div>

                {/* Connecting Line */}
                <div className="flex justify-center">
                  <div className="h-6 w-0.5 bg-slate-700" />
                </div>

                {/* Package Nodes Grid */}
                <div>
                  <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider text-center mb-3">
                    [DEPENDS_ON*] Direct &amp; Transitive Packages ({filteredPackages.length})
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 max-h-80 overflow-y-auto p-2 scrollbar-thin scrollbar-thumb-slate-800">
                    {filteredPackages.map((pkg) => {
                      const isVulnerable = vulnerablePkgNames.has(pkg.name)
                      const isSelected = selectedNode?.id === pkg.id

                      return (
                        <button
                          key={pkg.id}
                          type="button"
                          onClick={() =>
                            setSelectedNode({
                              type: 'package',
                              id: pkg.id,
                              name: pkg.name,
                              meta: pkg,
                            })
                          }
                          className={`flex items-center justify-between rounded-lg border p-2.5 text-left text-xs transition-all ${
                            isSelected
                              ? 'border-sky-400 bg-sky-500/20 text-white ring-1 ring-sky-400'
                              : isVulnerable
                              ? 'border-rose-500/40 bg-rose-500/10 text-rose-200 hover:border-rose-400'
                              : 'border-slate-800 bg-[#0f1822] text-slate-300 hover:border-slate-700 hover:bg-slate-900'
                          }`}
                        >
                          <div className="truncate pr-2">
                            <div className="font-semibold truncate">{pkg.name}</div>
                            <div className="font-mono text-[10px] text-slate-400">
                              @{pkg.version}
                            </div>
                          </div>
                          {isVulnerable ? (
                            <ShieldAlert className="h-4 w-4 text-rose-400 shrink-0" aria-hidden="true" />
                          ) : (
                            <Package className="h-3.5 w-3.5 text-slate-500 shrink-0" aria-hidden="true" />
                          )}
                        </button>
                      )
                    })}
                  </div>
                </div>

                {/* Vulnerability Leaf Nodes */}
                {findings.length > 0 && (
                  <div>
                    <div className="flex justify-center my-2">
                      <div className="h-6 w-0.5 bg-rose-500/50" />
                    </div>
                    <div className="text-[11px] font-semibold text-rose-400 uppercase tracking-wider text-center mb-2">
                      [AFFECTS] Linked Vulnerability Nodes ({findings.length})
                    </div>
                    <div className="flex flex-wrap justify-center gap-2">
                      {findings.map((f) => (
                        <button
                          key={f.id}
                          type="button"
                          onClick={() =>
                            setSelectedNode({
                              type: 'vulnerability',
                              id: f.id,
                              name: f.id,
                              meta: f,
                            })
                          }
                          className="flex items-center gap-1.5 rounded-lg border border-red-500/40 bg-red-500/15 px-3 py-1.5 text-[11px] font-mono font-semibold text-red-300 hover:bg-red-500/25 transition-colors"
                        >
                          <ShieldAlert className="h-3.5 w-3.5" />
                          <span>{f.id}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Node Inspector Drawer */}
        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <Eye className="h-4 w-4 text-sky-400" />
            <h2 className="text-sm font-bold text-white">Node Inspector</h2>
          </div>

          {selectedNode ? (
            <div className="space-y-4 text-xs">
              <div>
                <span className="text-[10px] font-bold uppercase tracking-wider text-sky-400">
                  {selectedNode.type} Node
                </span>
                <h3 className="text-base font-bold text-white mt-0.5 break-all">
                  {selectedNode.name}
                </h3>
              </div>

              <div className="space-y-2.5 rounded-lg border border-slate-800 bg-[#0b121a] p-3 text-slate-300">
                <div className="flex items-center justify-between">
                  <span className="text-slate-500">Node Identifier:</span>
                  <span className="font-mono text-[11px] text-slate-300 break-all">
                    {selectedNode.id}
                  </span>
                </div>

                {selectedNode.type === 'package' && (
                  <>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Version:</span>
                      <span className="font-mono font-semibold text-sky-300">
                        {selectedNode.meta?.version}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Ecosystem:</span>
                      <span className="uppercase font-semibold">
                        {selectedNode.meta?.ecosystem}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Affected Status:</span>
                      <span
                        className={`font-semibold ${
                          vulnerablePkgNames.has(selectedNode.name)
                            ? 'text-rose-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {vulnerablePkgNames.has(selectedNode.name)
                          ? 'Vulnerable'
                          : 'No Known Vulnerabilities'}
                      </span>
                    </div>
                  </>
                )}

                {selectedNode.type === 'vulnerability' && (
                  <>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Severity:</span>
                      <span className="font-bold text-red-400 uppercase">
                        {selectedNode.meta?.severity}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Target Package:</span>
                      <span className="font-semibold text-white">
                        {selectedNode.meta?.package_name}@{selectedNode.meta?.package_version}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Fixed In:</span>
                      <span className="font-mono text-emerald-400 font-semibold">
                        {selectedNode.meta?.fixed_version
                          ? `>= ${selectedNode.meta.fixed_version}`
                          : 'None'}
                      </span>
                    </div>
                    <div className="pt-2 border-t border-slate-800">
                      <Link
                        to={`/findings/${selectedNode.id}`}
                        className="inline-flex items-center gap-1 text-sky-400 hover:text-sky-300 font-semibold"
                      >
                        <span>View complete finding detail</span>
                        <ExternalLink className="h-3 w-3" />
                      </Link>
                    </div>
                  </>
                )}
              </div>

              <div className="rounded-lg border border-slate-800/80 bg-slate-900/40 p-3 text-[11px] text-slate-400">
                <strong>FalkorDB Provenance:</strong> Node properties are backed by parameterized
                Cypher queries adhering to Vulnify graph schema rules.
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-xs text-slate-500">
              Click any node in the graph map to inspect its attributes, relationships, and fixed
              versions.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
