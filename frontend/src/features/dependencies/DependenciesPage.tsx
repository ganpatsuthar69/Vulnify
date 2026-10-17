import { useState, useEffect, useCallback } from 'react'
import {
  Package,
  Search,
  ExternalLink,
  Loader2,
  RefreshCw,
  AlertCircle,
  UploadCloud,
} from 'lucide-react'
import { Link } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import { getProjectPackages } from '@/features/projects/projectApi'
import type { PackageVersion } from '@/features/projects/types'

export function DependenciesPage() {
  const { activeProject } = useProjects()

  const [packages, setPackages] = useState<PackageVersion[]>([])
  const [searchTerm, setSearchTerm] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadPackages = useCallback(async (projectId: string) => {
    setIsLoading(true)
    setError(null)
    try {
      const data = await getProjectPackages(projectId)
      setPackages(data)
    } catch {
      setError('Failed to load project packages from FalkorDB.')
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    if (activeProject) {
      void loadPackages(activeProject.id)
    } else {
      setPackages([])
    }
  }, [activeProject, loadPackages])

  const filteredPackages = packages.filter(
    (p) =>
      p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.version.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.purl.toLowerCase().includes(searchTerm.toLowerCase()),
  )

  if (!activeProject) {
    return (
      <div className="rounded-xl border border-dashed border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
        <AlertCircle className="mx-auto h-8 w-8 text-amber-400" aria-hidden="true" />
        <h2 className="mt-3 text-sm font-bold text-white">No Active Project Selected</h2>
        <p className="mt-1 text-slate-400">
          Please select or create a project in the top navigation bar to view dependencies.
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
            <h1 className="text-xl font-bold text-white">Dependencies Inventory</h1>
            <span className="rounded-full bg-slate-800 px-2.5 py-0.5 text-xs font-semibold text-slate-300">
              {packages.length} packages
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Reachable <code className="text-slate-300">PackageVersion</code> nodes stored in FalkorDB
            for service manifests in{' '}
            <span className="font-semibold text-slate-200">{activeProject.name}</span>.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Link
            to="/import"
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-sky-400 transition-colors"
          >
            <UploadCloud className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Import Lockfile</span>
          </Link>
          <button
            type="button"
            onClick={() => void loadPackages(activeProject.id)}
            disabled={isLoading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-700 hover:text-white transition-colors disabled:opacity-50"
            title="Refresh packages"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin text-sky-400' : ''}`}
              aria-hidden="true"
            />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div
          role="alert"
          className="flex items-center justify-between rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-200"
        >
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-rose-400 shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </div>
          <button
            type="button"
            onClick={() => void loadPackages(activeProject.id)}
            className="rounded bg-rose-500/20 px-2.5 py-1 font-semibold text-rose-200 hover:bg-rose-500/30"
          >
            Retry
          </button>
        </div>
      )}

      {/* Search and Filters Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 rounded-xl border border-slate-800 bg-[#0f1822] p-4">
        <div className="relative w-full sm:w-80">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" aria-hidden="true" />
          <input
            type="search"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by package name or version..."
            className="w-full rounded-lg border border-slate-700 bg-[#0b121a] py-2 pl-9 pr-3 text-xs text-slate-200 placeholder-slate-500 transition-colors focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
          />
        </div>

        <div className="flex items-center gap-2 text-xs text-slate-400 w-full sm:w-auto justify-end">
          <span>Showing:</span>
          <span className="font-semibold text-white">
            {filteredPackages.length} of {packages.length}
          </span>
        </div>
      </div>

      {/* Table / List */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] shadow-xl overflow-hidden">
        {isLoading ? (
          <div className="flex flex-col items-center justify-center p-12 text-slate-400">
            <Loader2 className="h-8 w-8 animate-spin text-sky-400" aria-hidden="true" />
            <span className="mt-3 text-xs font-medium text-slate-300">
              Querying PackageVersion graph nodes...
            </span>
          </div>
        ) : packages.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-400">
            <Package className="mx-auto h-8 w-8 text-slate-600" aria-hidden="true" />
            <h3 className="mt-3 font-semibold text-white">No dependencies imported</h3>
            <p className="mt-1 text-slate-500">
              Upload a lockfile in the Import Data page to populate this inventory.
            </p>
            <Link
              to="/import"
              className="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-2 text-xs font-semibold text-white hover:bg-sky-400 transition-colors"
            >
              <UploadCloud className="h-3.5 w-3.5" />
              <span>Import Lockfile</span>
            </Link>
          </div>
        ) : filteredPackages.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-400">
            No package versions match "<span className="text-white">{searchTerm}</span>".
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/40 text-slate-400">
                  <th className="py-3 px-4 font-semibold">Package Name</th>
                  <th className="py-3 px-4 font-semibold">Installed Version</th>
                  <th className="py-3 px-4 font-semibold">Ecosystem</th>
                  <th className="py-3 px-4 font-semibold">PURL Identifier</th>
                  <th className="py-3 px-4 font-semibold text-right">External Registry</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredPackages.map((pkg) => {
                  const registryUrl =
                    pkg.ecosystem.toLowerCase() === 'npm'
                      ? `https://www.npmjs.com/package/${pkg.name}/v/${pkg.version}`
                      : `https://pypi.org/project/${pkg.name}/${pkg.version}/`

                  return (
                    <tr key={pkg.id} className="hover:bg-slate-900/40 transition-colors">
                      <td className="py-3 px-4 font-semibold text-white flex items-center gap-2">
                        <Package className="h-4 w-4 text-slate-500" aria-hidden="true" />
                        <span>{pkg.name}</span>
                      </td>
                      <td className="py-3 px-4 font-mono font-medium text-sky-300">
                        {pkg.version}
                      </td>
                      <td className="py-3 px-4">
                        <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-bold text-slate-300 uppercase">
                          {pkg.ecosystem}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-400 break-all">
                        {pkg.purl}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <a
                          href={registryUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-400 hover:text-sky-300 transition-colors"
                          title={`View ${pkg.name} on ${pkg.ecosystem} registry`}
                        >
                          <span>Registry</span>
                          <ExternalLink className="h-3 w-3" aria-hidden="true" />
                        </a>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
