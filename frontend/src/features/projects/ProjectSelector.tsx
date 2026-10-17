import { ChevronDown, FolderGit2, Plus, Check } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useProjects } from './ProjectProvider'

interface ProjectSelectorProps {
  onOpenCreateModal: () => void
}

export function ProjectSelector({ onOpenCreateModal }: ProjectSelectorProps) {
  const { projects, activeProject, activeProjectId, selectProject, isLoading } = useProjects()
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  // Close dropdown on click outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [isOpen])

  // Handle escape key
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape' && isOpen) {
        setIsOpen(false)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen])

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-400">
        <FolderGit2 className="h-3.5 w-3.5 animate-pulse text-sky-400" aria-hidden="true" />
        <span>Loading projects...</span>
      </div>
    )
  }

  if (projects.length === 0) {
    return (
      <div className="flex items-center gap-2">
        <div className="flex items-center gap-1.5 rounded-lg border border-dashed border-slate-700 bg-slate-900/40 px-3 py-1.5 text-xs text-slate-400">
          <FolderGit2 className="h-3.5 w-3.5 text-slate-500" aria-hidden="true" />
          <span>No projects yet</span>
        </div>
        <button
          type="button"
          onClick={onOpenCreateModal}
          className="inline-flex items-center gap-1 rounded-lg border border-sky-500/40 bg-sky-500/10 px-2.5 py-1.5 text-xs font-semibold text-sky-300 transition-colors hover:border-sky-400 hover:bg-sky-500/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          aria-label="Create your first project"
        >
          <Plus className="h-3.5 w-3.5" aria-hidden="true" />
          <span>New Project</span>
        </button>
      </div>
    )
  }

  return (
    <div className="relative inline-block text-left" ref={dropdownRef}>
      <button
        type="button"
        id="project-selector-button"
        aria-haspopup="listbox"
        aria-expanded={isOpen}
        aria-label="Active Project: select project"
        onClick={() => setIsOpen((prev) => !prev)}
        className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-[#0b121a] px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:border-slate-600 hover:bg-slate-800/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
      >
        <FolderGit2 className="h-3.5 w-3.5 text-sky-400" aria-hidden="true" />
        <span className="max-w-[140px] truncate font-semibold text-white">
          {activeProject?.name ?? 'Select project'}
        </span>
        {activeProject && (
          <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-semibold text-slate-300 uppercase">
            {activeProject.ecosystem}
          </span>
        )}
        <ChevronDown
          className={`h-3 w-3 text-slate-400 transition-transform duration-150 ${isOpen ? 'rotate-180' : ''}`}
          aria-hidden="true"
        />
      </button>

      {isOpen && (
        <div
          role="listbox"
          aria-labelledby="project-selector-button"
          className="absolute left-0 z-50 mt-1.5 w-64 origin-top-left rounded-lg border border-slate-700 bg-[#0f1822] p-1.5 shadow-2xl backdrop-blur-md focus:outline-none"
        >
          <div className="px-2 py-1 text-[11px] font-semibold tracking-wider text-slate-400 uppercase">
            Switch Project
          </div>

          <div className="max-h-56 overflow-y-auto py-1">
            {projects.map((proj) => {
              const isSelected = proj.id === activeProjectId
              return (
                <button
                  key={proj.id}
                  type="button"
                  role="option"
                  aria-selected={isSelected}
                  onClick={() => {
                    selectProject(proj.id)
                    setIsOpen(false)
                  }}
                  className={`flex w-full items-center justify-between rounded-md px-2.5 py-2 text-left text-xs transition-colors ${
                    isSelected
                      ? 'bg-sky-500/15 text-white font-medium'
                      : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                  }`}
                >
                  <div className="flex flex-col truncate pr-2">
                    <span className="truncate font-semibold">{proj.name}</span>
                    <span className="text-[10px] text-slate-400 uppercase">{proj.ecosystem}</span>
                  </div>
                  {isSelected && <Check className="h-4 w-4 text-sky-400 flex-shrink-0" aria-hidden="true" />}
                </button>
              )
            })}
          </div>

          <div className="mt-1 border-t border-slate-800 pt-1">
            <button
              type="button"
              onClick={() => {
                setIsOpen(false)
                onOpenCreateModal()
              }}
              className="flex w-full items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-semibold text-sky-400 transition-colors hover:bg-sky-500/10 hover:text-sky-300"
            >
              <Plus className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Create New Project</span>
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
