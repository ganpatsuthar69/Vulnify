import {
  AlertCircle,
  Check,
  FolderGit2,
  Loader2,
  Lock,
  LogOut,
  Plus,
  RefreshCw,
  User as UserIcon,
} from 'lucide-react'
import { useState } from 'react'
import { useAuth } from './AuthProvider'
import { CreateProjectModal } from '@/features/projects/CreateProjectModal'
import { ProjectSelector } from '@/features/projects/ProjectSelector'
import { useProjects } from '@/features/projects/ProjectProvider'
import { LockfileImportCard } from '@/features/dependencies/LockfileImportCard'
import { OsvAdvisoryCard } from '@/features/advisories/OsvAdvisoryCard'
import { VersionMatchingCard } from '@/features/advisories/VersionMatchingCard'
import vulnifyLogo from '@/assets/vulnify-logo.png'

export function DashboardPage() {
  const { user, logout } = useAuth()
  const {
    projects,
    activeProject,
    activeProjectId,
    isLoading,
    error,
    selectProject,
    refreshProjects,
  } = useProjects()

  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false)
  const isAdmin = user?.role === 'admin'

  return (
    <div className="flex min-h-screen flex-col bg-[#0b121a] text-slate-200">
      {/* Top Navigation Bar */}
      <header className="border-b border-slate-800 bg-[#0f1822]/80 px-6 py-3.5 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-3">
              <img
                src={vulnifyLogo}
                alt="Vulnify"
                className="h-8 w-auto object-contain"
              />
              <span className="text-lg font-bold tracking-tight text-white">Vulnify</span>
            </div>

            {/* Top-Bar Project Selector */}
            <div className="hidden sm:block border-l border-slate-800 pl-6">
              <ProjectSelector onOpenCreateModal={() => setIsCreateModalOpen(true)} />
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-slate-300">
                {user?.name ?? 'User'}
              </span>
              <span
                className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold tracking-wide uppercase ${
                  isAdmin
                    ? 'border border-sky-400/30 bg-sky-500/10 text-sky-300'
                    : 'border border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                }`}
              >
                {user?.role ?? 'user'}
              </span>
            </div>
            <button
              type="button"
              onClick={() => void logout()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-semibold text-slate-200 transition-colors hover:border-slate-600 hover:bg-slate-700 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
              Sign out
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="mx-auto flex w-full max-w-6xl flex-1 flex-col p-6 space-y-6">
        {/* Mobile Project Selector */}
        <div className="block sm:hidden rounded-lg border border-slate-800 bg-[#0f1822] p-3">
          <div className="text-xs font-semibold text-slate-400 mb-2">Active Project</div>
          <ProjectSelector onOpenCreateModal={() => setIsCreateModalOpen(true)} />
        </div>

        {/* Error State */}
        {error && (
          <div
            role="alert"
            className="flex items-center justify-between rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-xs text-red-300"
          >
            <div className="flex items-center gap-2">
              <AlertCircle className="h-4 w-4 flex-shrink-0 text-red-400" aria-hidden="true" />
              <span>{error}</span>
            </div>
            <button
              type="button"
              onClick={() => void refreshProjects()}
              className="inline-flex items-center gap-1 rounded bg-red-500/20 px-2.5 py-1 font-semibold text-red-200 hover:bg-red-500/30"
            >
              <RefreshCw className="h-3 w-3" aria-hidden="true" />
              <span>Retry</span>
            </button>
          </div>
        )}

        {/* Loading State */}
        {isLoading && (
          <div
            role="status"
            aria-live="polite"
            className="flex flex-col items-center justify-center rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-slate-400"
          >
            <Loader2 className="h-8 w-8 animate-spin text-sky-400" aria-hidden="true" />
            <span className="mt-3 text-sm font-medium text-slate-300">Loading projects from FalkorDB...</span>
          </div>
        )}

        {/* Empty State */}
        {!isLoading && !error && projects.length === 0 && (
          <div
            role="region"
            aria-label="Empty projects state"
            className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 bg-[#0f1822] p-12 text-center"
          >
            <div className="flex h-14 w-14 items-center justify-center rounded-full bg-slate-800/80 ring-1 ring-slate-700">
              <FolderGit2 className="h-7 w-7 text-sky-400" aria-hidden="true" />
            </div>
            <h3 className="mt-4 text-base font-semibold text-white">No projects yet</h3>
            <p className="mt-2 max-w-md text-sm text-slate-400">
              No projects yet. Create your first project to start analyzing its dependencies.
            </p>
            <button
              type="button"
              onClick={() => setIsCreateModalOpen(true)}
              className="mt-6 inline-flex items-center gap-2 rounded-lg border border-sky-500 bg-sky-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-sky-600/20 transition-all hover:bg-sky-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              <Plus className="h-4 w-4" aria-hidden="true" />
              <span>Create Project</span>
            </button>
          </div>
        )}

        {/* Populated State */}
        {!isLoading && !error && projects.length > 0 && (
          <>
            {/* Active Project Banner */}
            {activeProject && (
              <div className="rounded-xl border border-sky-500/30 bg-sky-500/5 p-5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2.5">
                      <span className="rounded-full bg-sky-500/20 px-2 py-0.5 text-[10px] font-bold text-sky-300 tracking-wide uppercase">
                        Active Project
                      </span>
                      <h2 className="text-xl font-bold text-white">{activeProject.name}</h2>
                      <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-semibold text-slate-300 uppercase">
                        {activeProject.ecosystem}
                      </span>
                    </div>
                    {activeProject.description && (
                      <p className="mt-1.5 text-xs text-slate-300 max-w-2xl">
                        {activeProject.description}
                      </p>
                    )}
                    <div className="mt-2 text-[11px] font-mono text-slate-500">
                      ID: {activeProject.id}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 flex-shrink-0">
                    <button
                      type="button"
                      onClick={() => setIsCreateModalOpen(true)}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-semibold text-slate-200 transition-colors hover:bg-slate-700 hover:text-white"
                    >
                      <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>New Project</span>
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Lockfile Dependency Ingestion (US-102) */}
            {activeProject && <LockfileImportCard project={activeProject} />}

            {/* OSV Advisory Ingestion (US-103) */}
            {activeProject && <OsvAdvisoryCard project={activeProject} />}

            {/* Ecosystem-Aware Version Matching (US-104) */}
            {activeProject && <VersionMatchingCard project={activeProject} />}

            {/* Projects Directory List */}
            <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl">
              <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-white">Projects</h3>
                  <span className="rounded-full bg-slate-800 px-2 py-0.5 text-xs font-semibold text-slate-400">
                    {projects.length}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(true)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/10 px-3 py-1.5 text-xs font-semibold text-sky-300 transition-colors hover:border-sky-400 hover:bg-sky-500/20"
                >
                  <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Create Project</span>
                </button>
              </div>

              <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {projects.map((proj) => {
                  const isActive = proj.id === activeProjectId
                  return (
                    <div
                      key={proj.id}
                      className={`flex flex-col justify-between rounded-lg border p-4 transition-all ${
                        isActive
                          ? 'border-sky-500/60 bg-sky-500/5 shadow-md shadow-sky-500/5 ring-1 ring-sky-500/30'
                          : 'border-slate-800 bg-[#0b121a] hover:border-slate-700 hover:bg-slate-900/60'
                      }`}
                    >
                      <div>
                        <div className="flex items-start justify-between gap-2">
                          <h4 className="font-semibold text-white truncate text-sm" title={proj.name}>
                            {proj.name}
                          </h4>
                          <span
                            className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${
                              proj.ecosystem === 'npm'
                                ? 'bg-sky-500/20 text-sky-300'
                                : 'bg-emerald-500/20 text-emerald-300'
                            }`}
                          >
                            {proj.ecosystem}
                          </span>
                        </div>

                        {proj.description ? (
                          <p className="mt-2 text-xs text-slate-400 line-clamp-2" title={proj.description}>
                            {proj.description}
                          </p>
                        ) : (
                          <p className="mt-2 text-xs text-slate-600 italic">No description provided</p>
                        )}
                      </div>

                      <div className="mt-4 flex items-center justify-between border-t border-slate-800/80 pt-3">
                        <span className="text-[10px] text-slate-500">
                          {new Date(proj.created_at * 1000).toLocaleDateString(undefined, {
                            month: 'short',
                            day: 'numeric',
                            year: 'numeric',
                          })}
                        </span>

                        {isActive ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-sky-400">
                            <Check className="h-3.5 w-3.5" aria-hidden="true" />
                            <span>Active</span>
                          </span>
                        ) : (
                          <button
                            type="button"
                            onClick={() => selectProject(proj.id)}
                            className="rounded px-2.5 py-1 text-xs font-semibold text-slate-300 transition-colors hover:bg-slate-800 hover:text-white"
                          >
                            Select
                          </button>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          </>
        )}

        {/* User Account / Role Details Card */}
        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-slate-800 ring-1 ring-slate-700">
              {isAdmin ? (
                <Lock className="h-6 w-6 text-sky-400" aria-hidden="true" />
              ) : (
                <UserIcon className="h-6 w-6 text-emerald-400" aria-hidden="true" />
              )}
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">{user?.name}</h2>
              <p className="text-xs text-slate-400">{user?.email}</p>
            </div>
          </div>

          <div className="mt-4 rounded-lg border border-slate-800 bg-[#0b121a] p-3">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Account Role</span>
              <span className="font-semibold text-slate-200 uppercase">{user?.role}</span>
            </div>
            <div className="mt-1.5 flex items-center justify-between text-xs text-slate-400">
              <span>User ID</span>
              <span className="font-mono text-slate-300">{user?.id}</span>
            </div>
          </div>

          {isAdmin ? (
            <div className="mt-4 rounded-lg border border-sky-500/20 bg-sky-500/5 p-3 text-xs text-sky-300">
              <strong>Administrator Privileges Active:</strong> You have permission to manage workspace projects and analyze dependency graphs.
            </div>
          ) : (
            <div className="mt-4 rounded-lg border border-slate-800 bg-slate-900/40 p-3 text-xs text-slate-400">
              Standard workspace member access. Dependency graph and exposure analysis tools are active.
            </div>
          )}
        </div>
      </main>

      {/* Create Project Modal */}
      <CreateProjectModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
      />
    </div>
  )
}
