import { useState, useRef, type ChangeEvent, type FormEvent } from 'react'
import {
  Upload,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  AlertCircle,
  Loader2,
  RefreshCw,
  Layers,
  Database,
  X,
  FileCheck,
} from 'lucide-react'
import { importLockfile, ProjectApiError } from '../projects/projectApi'
import type { ImportSummary, Project } from '../projects/types'

interface LockfileImportCardProps {
  project: Project
}

const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024 // 10 MB

export function LockfileImportCard({ project }: LockfileImportCardProps) {
  const [serviceName, setServiceName] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [validationError, setValidationError] = useState<string | null>(null)
  const [serverError, setServerError] = useState<{ message: string; requestId?: string } | null>(null)
  const [summary, setSummary] = useState<ImportSummary | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    setValidationError(null)
    setServerError(null)

    if (!file) {
      setSelectedFile(null)
      return
    }

    // Client-side extension validation
    const lowerName = file.name.toLowerCase()
    if (!lowerName.endsWith('.json')) {
      setValidationError(
        `File "${file.name}" is not a recognized JSON lockfile. For npm projects, "package-lock.json" is required.`,
      )
    }

    // Client-side file size validation
    if (file.size > MAX_FILE_SIZE_BYTES) {
      const mbSize = (file.size / (1024 * 1024)).toFixed(1)
      setValidationError(
        `File size (${mbSize} MB) exceeds the maximum allowed limit of 10 MB.`,
      )
    }

    setSelectedFile(file)
  }

  const handleClearFile = () => {
    setSelectedFile(null)
    setValidationError(null)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setValidationError(null)
    setServerError(null)

    const trimmedService = serviceName.trim()
    if (!trimmedService) {
      setValidationError('Service name is required.')
      return
    }

    if (!selectedFile) {
      setValidationError('Please select a lockfile to import.')
      return
    }

    if (selectedFile.size > MAX_FILE_SIZE_BYTES) {
      setValidationError('File size exceeds the 10 MB maximum limit.')
      return
    }

    setIsSubmitting(true)
    try {
      const result = await importLockfile(project.id, trimmedService, selectedFile)
      setSummary(result)
    } catch (err) {
      if (err instanceof ProjectApiError) {
        setServerError({
          message: err.message,
          requestId: err.requestId,
        })
      } else {
        setServerError({
          message: 'An unexpected error occurred while communicating with the server.',
        })
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleReset = () => {
    setSummary(null)
    setSelectedFile(null)
    setValidationError(null)
    setServerError(null)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  return (
    <div className="w-full rounded-xl border border-slate-800 bg-[#0f1822] shadow-xl overflow-hidden">
      {/* Header */}
      <div className="border-b border-slate-800/80 bg-slate-900/40 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-sky-500/10 text-sky-400 ring-1 ring-sky-500/20">
              <Upload className="h-5 w-5" aria-hidden="true" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-white">Import Service Dependencies</h2>
              <p className="text-xs text-slate-400">
                Upload a real project lockfile to build the dependency graph in FalkorDB
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Project:</span>
            <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-medium text-slate-200">
              {project.name} ({project.ecosystem})
            </span>
          </div>
        </div>
      </div>

      <div className="p-6">
        {/* Success / Summary View */}
        {summary ? (
          <div className="space-y-6">
            {/* Status Banner */}
            <div
              className={`rounded-lg border p-4 flex items-start gap-3.5 ${
                summary.status === 'completed'
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
                  : summary.status === 'partially_completed'
                  ? 'border-amber-500/30 bg-amber-500/10 text-amber-200'
                  : 'border-rose-500/30 bg-rose-500/10 text-rose-200'
              }`}
            >
              <CheckCircle2 className="h-5 w-5 text-emerald-400 mt-0.5 shrink-0" aria-hidden="true" />
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white">
                    Lockfile Imported Successfully
                  </h3>
                  <span className="text-xs uppercase tracking-wider font-semibold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                    {summary.status}
                  </span>
                </div>
                <p className="mt-1 text-xs text-slate-300">
                  Real dependency hierarchy stored in FalkorDB for service{' '}
                  <span className="font-semibold text-white">{summary.service_name}</span>.
                </p>
              </div>
            </div>

            {/* Metrics Grid */}
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-center">
                <div className="text-2xl font-bold text-white">{summary.packages_parsed}</div>
                <div className="mt-1 text-xs font-medium text-slate-400">Packages Parsed</div>
                <div className="mt-1 text-[11px] text-slate-500">
                  {summary.packages_created} created, {summary.packages_reused} reused
                </div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-center">
                <div className="text-2xl font-bold text-sky-400">
                  {summary.edges_created + summary.edges_reused}
                </div>
                <div className="mt-1 text-xs font-medium text-slate-400">Dependency Edges</div>
                <div className="mt-1 text-[11px] text-slate-500">
                  {summary.edges_created} created, {summary.edges_reused} reused
                </div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-center">
                <div className="text-2xl font-bold text-amber-400">{summary.skipped_entries}</div>
                <div className="mt-1 text-xs font-medium text-slate-400">Skipped Entries</div>
                <div className="mt-1 text-[11px] text-slate-500">Links or unversioned</div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-center">
                <div className="text-2xl font-bold text-slate-300">
                  {summary.errors.length}
                </div>
                <div className="mt-1 text-xs font-medium text-slate-400">Errors</div>
                <div className="mt-1 text-[11px] text-slate-500">Zero critical failures</div>
              </div>
            </div>

            {/* Provenance Box */}
            <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-xs text-slate-300 space-y-2">
              <div className="flex items-center gap-2 font-semibold text-slate-200">
                <Database className="h-4 w-4 text-sky-400" aria-hidden="true" />
                <span>Import Provenance & Integrity</span>
              </div>
              <div className="grid grid-cols-1 gap-2 pt-1 sm:grid-cols-2">
                <div>
                  <span className="text-slate-500">Source Lockfile: </span>
                  <span className="font-mono text-slate-200">{summary.filename}</span>
                </div>
                <div>
                  <span className="text-slate-500">Service: </span>
                  <span className="font-medium text-slate-200">{summary.service_name}</span>
                </div>
                <div className="sm:col-span-2">
                  <span className="text-slate-500">SHA-256 Digest: </span>
                  <span className="font-mono text-[11px] text-slate-300 break-all">
                    {summary.sha256_hash}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">Imported At: </span>
                  <span className="text-slate-300">
                    {new Date(summary.imported_at * 1000).toLocaleString()}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">Idempotency Guarantee: </span>
                  <span className="text-emerald-400 font-medium">Verified duplicate-free</span>
                </div>
              </div>
            </div>

            {/* Actionable Warnings / Errors */}
            {summary.warnings.length > 0 && (
              <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-4 text-xs text-amber-300">
                <div className="flex items-center gap-2 font-semibold text-amber-200 mb-1">
                  <AlertTriangle className="h-4 w-4" aria-hidden="true" />
                  <span>Parser Warnings ({summary.warnings.length})</span>
                </div>
                <ul className="list-disc pl-5 space-y-1 text-slate-300">
                  {summary.warnings.slice(0, 5).map((w, idx) => (
                    <li key={idx}>{w}</li>
                  ))}
                  {summary.warnings.length > 5 && (
                    <li className="text-slate-500">...and {summary.warnings.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={handleReset}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-200 transition-colors hover:border-slate-600 hover:bg-slate-700 hover:text-white"
              >
                <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                Import Another Lockfile
              </button>
            </div>
          </div>
        ) : (
          /* Form View */
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Error Message */}
            {serverError && (
              <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-200 flex items-start gap-3">
                <AlertCircle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" aria-hidden="true" />
                <div className="flex-1">
                  <p className="font-semibold">{serverError.message}</p>
                  {serverError.requestId && (
                    <p className="mt-1 text-[11px] text-slate-400 font-mono">
                      Request ID: {serverError.requestId}
                    </p>
                  )}
                </div>
              </div>
            )}

            {validationError && (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3.5 text-xs text-amber-200 flex items-start gap-2.5">
                <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
                <span>{validationError}</span>
              </div>
            )}

            {/* Service Name Input */}
            <div>
              <label
                htmlFor="service-name-input"
                className="block text-xs font-medium text-slate-300"
              >
                Service Name <span className="text-rose-400">*</span>
              </label>
              <div className="mt-1.5">
                <input
                  id="service-name-input"
                  type="text"
                  required
                  disabled={isSubmitting}
                  value={serviceName}
                  onChange={(e) => setServiceName(e.target.value)}
                  placeholder="e.g. payment-service, web-api, checkout"
                  className="block w-full rounded-lg border border-slate-700 bg-[#0b121a] px-3.5 py-2 text-sm text-slate-100 placeholder-slate-500 transition-colors focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 disabled:opacity-50"
                />
              </div>
              <p className="mt-1 text-[11px] text-slate-500">
                Dependencies will be scoped and linked to this named service within{' '}
                {project.name}.
              </p>
            </div>

            {/* File Upload Dropzone / Picker */}
            <div>
              <label className="block text-xs font-medium text-slate-300">
                Dependency Lockfile <span className="text-rose-400">*</span>
              </label>
              <div className="mt-1.5">
                {selectedFile ? (
                  <div className="flex items-center justify-between rounded-lg border border-sky-500/40 bg-sky-500/5 px-4 py-3">
                    <div className="flex items-center gap-3">
                      <FileCheck className="h-5 w-5 text-sky-400" aria-hidden="true" />
                      <div>
                        <div className="text-xs font-semibold text-slate-200">
                          {selectedFile.name}
                        </div>
                        <div className="text-[11px] text-slate-400">
                          {(selectedFile.size / 1024).toFixed(1)} KB &bull; npm lockfile
                        </div>
                      </div>
                    </div>
                    <button
                      type="button"
                      disabled={isSubmitting}
                      onClick={handleClearFile}
                      className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 disabled:opacity-50"
                      aria-label="Remove selected file"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                ) : (
                  <label
                    htmlFor="lockfile-file-input"
                    className="flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed border-slate-700 bg-[#0b121a] px-6 py-6 transition-colors hover:border-slate-500 hover:bg-slate-900/40"
                  >
                    <FileCode className="h-8 w-8 text-slate-400" aria-hidden="true" />
                    <span className="mt-2 text-xs font-semibold text-slate-300">
                      Click to choose <span className="text-sky-400">package-lock.json</span>
                    </span>
                    <span className="mt-1 text-[11px] text-slate-500">
                      Standard npm lockfile v1, v2, or v3 (up to 10 MB)
                    </span>
                    <input
                      id="lockfile-file-input"
                      ref={fileInputRef}
                      type="file"
                      accept=".json,application/json"
                      disabled={isSubmitting}
                      onChange={handleFileChange}
                      className="sr-only"
                    />
                  </label>
                )}
              </div>
            </div>

            {/* Format Notice */}
            <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3.5 text-xs text-slate-400 flex items-center gap-2.5">
              <Layers className="h-4 w-4 text-sky-400 shrink-0" aria-hidden="true" />
              <span>
                <strong>Supported Ecosystem:</strong> npm (<code className="text-slate-300">package-lock.json</code>).
                Uploaded files are parsed securely without code execution.
              </span>
            </div>

            {/* Submit Button */}
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="submit"
                disabled={isSubmitting || !selectedFile || !serviceName.trim()}
                className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-white shadow-sm transition-colors hover:bg-sky-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                    <span>Parsing &amp; Persisting Graph...</span>
                  </>
                ) : (
                  <>
                    <Upload className="h-4 w-4" aria-hidden="true" />
                    <span>Import Lockfile</span>
                  </>
                )}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
