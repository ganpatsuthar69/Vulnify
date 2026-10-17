import { useState, useMemo } from 'react'
import {
  FolderGit2,
  Plus,
  Search,
  Filter,
  CheckCircle,
  Calendar,
  Layers,
  ArrowRight,
} from 'lucide-react'
import { Link } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import { CreateProjectModal } from '@/features/projects/CreateProjectModal'
import type { SupportedEcosystem } from '@/features/projects/types'

export function ProjectsPage() {
  const { projects, activeProject, selectProject, isLoading } = useProjects()
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [ecosystemFilter, setEcosystemFilter] = useState<'ALL' | SupportedEcosystem>('ALL')

  const filteredProjects = useMemo(() => {
    return projects.filter((p) => {
      const matchesSearch =
        p.name.toLowerCase().includes(search.toLowerCase()) ||
        p.id.toLowerCase().includes(search.toLowerCase()) ||
        (p.description && p.description.toLowerCase().includes(search.toLowerCase()))

      const matchesEco = ecosystemFilter === 'ALL' || p.ecosystem === ecosystemFilter

      return matchesSearch && matchesEco
    })
  }, [projects, search, ecosystemFilter])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white">Project Workspaces</h1>
            <span className="rounded-full bg-sky-500/15 border border-sky-500/30 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-sky-300">
              {projects.length} Total
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Isolated security workspaces and dependency knowledge graphs partitioned by ecosystem.
          </p>
        </div>

        <button
          type="button"
          onClick={() => setIsCreateOpen(true)}
          className="flex items-center gap-2 rounded-lg bg-sky-500 px-3.5 py-2 text-xs font-semibold text-white shadow-sm hover:bg-sky-400 transition"
        >
          <Plus className="h-4 w-4" />
          Create Project
        </button>
      </div>

      {/* Search & Filter Bar */}
      <div className="flex flex-col sm:flex-row items-center gap-3">
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search projects by name, description, or ID..."
            className="w-full rounded-lg border border-slate-800 bg-[#0f1822] py-2 pl-9 pr-3 text-xs text-slate-200 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="h-3.5 w-3.5 text-slate-400 shrink-0" />
          <select
            value={ecosystemFilter}
            onChange={(e) => setEcosystemFilter(e.target.value as 'ALL' | SupportedEcosystem)}
            className="rounded-lg border border-slate-800 bg-[#0f1822] px-3 py-2 text-xs text-slate-300 focus:border-sky-500 focus:outline-none"
          >
            <option value="ALL">All Ecosystems</option>
            <option value="npm">npm (JavaScript)</option>
            <option value="PyPI">PyPI (Python)</option>
          </select>
        </div>
      </div>

      {/* Projects Grid */}
      {isLoading ? (
        <div className="p-12 text-center text-xs text-slate-400">Loading project catalog...</div>
      ) : filteredProjects.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-center space-y-3">
          <FolderGit2 className="h-10 w-10 text-slate-600 mx-auto" />
          <h3 className="text-sm font-semibold text-slate-300">No projects found</h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            Create a new security project to ingest dependency lockfiles and evaluate exposure paths.
          </p>
          <button
            type="button"
            onClick={() => setIsCreateOpen(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-sky-400"
          >
            <Plus className="h-3.5 w-3.5" />
            Create First Project
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filteredProjects.map((p) => {
            const isActive = activeProject?.id === p.id
            const dateStr = new Date(p.created_at * 1000).toLocaleDateString()

            return (
              <div
                key={p.id}
                className={`flex flex-col justify-between rounded-xl border p-5 shadow-lg transition-all ${
                  isActive
                    ? 'border-sky-500/50 bg-[#0f1822] ring-1 ring-sky-500/30'
                    : 'border-slate-800 bg-[#0f1822] hover:border-slate-700'
                }`}
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <h3 className="text-sm font-bold text-white">{p.name}</h3>
                        {isActive && (
                          <span className="flex items-center gap-1 rounded-full bg-sky-500/20 border border-sky-500/40 px-2 py-0.5 text-[9px] font-bold text-sky-300">
                            <CheckCircle className="h-2.5 w-2.5" /> Active
                          </span>
                        )}
                      </div>
                      <div className="font-mono text-[10px] text-slate-500">ID: {p.id}</div>
                    </div>

                    <span
                      className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                        p.ecosystem === 'npm'
                          ? 'bg-rose-500/15 border border-rose-500/30 text-rose-300'
                          : 'bg-indigo-500/15 border border-indigo-500/30 text-indigo-300'
                      }`}
                    >
                      {p.ecosystem}
                    </span>
                  </div>

                  <p className="text-xs text-slate-400 line-clamp-2">
                    {p.description || 'No description provided for this project workspace.'}
                  </p>
                </div>

                <div className="mt-5 pt-4 border-t border-slate-800/80 space-y-3">
                  <div className="flex items-center justify-between text-[11px] text-slate-500">
                    <span className="flex items-center gap-1">
                      <Calendar className="h-3 w-3" /> {dateStr}
                    </span>
                    <span>Graph: vulnify_{p.id.slice(0, 8)}</span>
                  </div>

                  <div className="flex items-center gap-2 pt-1">
                    {!isActive ? (
                      <button
                        type="button"
                        onClick={() => selectProject(p.id)}
                        className="flex-1 rounded-lg border border-slate-700 bg-slate-800/80 py-1.5 text-xs font-semibold text-slate-200 hover:border-sky-500 hover:text-white transition"
                      >
                        Set as Active
                      </button>
                    ) : (
                      <Link
                        to="/"
                        className="flex-1 flex items-center justify-center gap-1.5 rounded-lg bg-sky-500/15 border border-sky-500/30 py-1.5 text-xs font-semibold text-sky-300 hover:bg-sky-500/25 transition"
                      >
                        <span>Open Dashboard</span>
                        <ArrowRight className="h-3.5 w-3.5" />
                      </Link>
                    )}

                    <Link
                      to="/import"
                      onClick={() => !isActive && selectProject(p.id)}
                      title="Import data"
                      className="rounded-lg border border-slate-800 bg-[#0b121a] p-1.5 text-slate-400 hover:text-slate-200 hover:border-slate-700"
                    >
                      <Layers className="h-4 w-4" />
                    </Link>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Global Create Project Modal */}
      <CreateProjectModal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
      />
    </div>
  )
}
