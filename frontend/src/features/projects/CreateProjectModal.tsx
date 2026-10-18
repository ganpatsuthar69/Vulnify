import { useState, type FormEvent } from 'react'
import { FolderPlus, Loader2, X, AlertCircle } from 'lucide-react'
import { useProjects } from './ProjectProvider'
import { ProjectApiError } from './projectApi'
import type { SupportedEcosystem } from './types'

interface CreateProjectModalProps {
  isOpen: boolean
  onClose: () => void
}

export function CreateProjectModal({ isOpen, onClose }: CreateProjectModalProps) {
  const { createProject, capabilities } = useProjects()
  const [name, setName] = useState('')
  const [ecosystem, setEcosystem] = useState<SupportedEcosystem>('npm')
  const [description, setDescription] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!isOpen) return null

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)

    const trimmedName = name.trim()
    if (!trimmedName) {
      setError('Project name is required.')
      return
    }

    setIsSubmitting(true)
    try {
      await createProject({
        name: trimmedName,
        ecosystem,
        description: description.trim() || undefined,
      })
      setName('')
      setDescription('')
      onClose()
    } catch (err) {
      if (err instanceof ProjectApiError) {
        setError(err.message)
      } else {
        setError('Failed to create project.')
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="w-full max-w-md rounded-xl border border-slate-800 bg-[#0f1822] shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/50 px-6 py-4">
          <div className="flex items-center gap-2.5">
            <FolderPlus className="h-5 w-5 text-sky-400" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-white">Create New Project</h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200 flex items-start gap-2">
              <AlertCircle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label htmlFor="modal-project-name" className="block text-xs font-medium text-slate-300">
              Project Name <span className="text-rose-400">*</span>
            </label>
            <input
              id="modal-project-name"
              type="text"
              required
              disabled={isSubmitting}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Payment Service"
              className="mt-1.5 block w-full rounded-lg border border-slate-700 bg-[#0b121a] px-3.5 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 disabled:opacity-50"
            />
          </div>

          <div>
            <label htmlFor="modal-project-ecosystem" className="block text-xs font-medium text-slate-300">
              Package Ecosystem <span className="text-rose-400">*</span>
            </label>
            <select
              id="modal-project-ecosystem"
              value={ecosystem}
              disabled={isSubmitting}
              onChange={(e) => setEcosystem(e.target.value as SupportedEcosystem)}
              className="mt-1.5 block w-full rounded-lg border border-slate-700 bg-[#0b121a] px-3.5 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 disabled:opacity-50"
            >
              {capabilities && capabilities.length > 0 ? (
                capabilities.map((cap) => (
                  <option key={cap.id} value={cap.id}>
                    {cap.display_name}
                  </option>
                ))
              ) : (
                <>
                  <option value="npm">npm (Node.js)</option>
                  <option value="PyPI">PyPI (Python)</option>
                </>
              )}
            </select>
          </div>

          <div>
            <label htmlFor="modal-project-desc" className="block text-xs font-medium text-slate-300">
              Description <span className="text-slate-500">(Optional)</span>
            </label>
            <textarea
              id="modal-project-desc"
              rows={2}
              disabled={isSubmitting}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Brief summary of service dependencies..."
              className="mt-1.5 block w-full rounded-lg border border-slate-700 bg-[#0b121a] px-3.5 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 disabled:opacity-50"
            />
          </div>

          <div className="flex items-center justify-end gap-2.5 pt-3">
            <button
              type="button"
              disabled={isSubmitting}
              onClick={onClose}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !name.trim()}
              className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-400 disabled:opacity-50"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  <span>Creating...</span>
                </>
              ) : (
                <span>Create Project</span>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
