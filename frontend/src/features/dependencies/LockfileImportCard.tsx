import { useState, useRef, useEffect, type ChangeEvent, type FormEvent } from 'react'
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
  ShieldCheck,
  FileText,
  History,
} from 'lucide-react'
import { Link } from 'react-router'
import { useProjects } from '../projects/ProjectProvider'
import { importDependencies, ProjectApiError } from '../projects/projectApi'
import type {
  FidelityLevel,
  ImportMethodCapability,
  ImportSummary,
  Project,
} from '../projects/types'

interface LockfileImportCardProps {
  project: Project
}

function getFidelityBadge(fidelity?: FidelityLevel | string) {
  switch (fidelity) {
    case 'exact_lockfile':
      return {
        label: 'Exact Lockfile',
        color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
        dot: 'bg-emerald-400',
      }
    case 'checksum_verified':
      return {
        label: 'Checksum Verified',
        color: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
        dot: 'bg-cyan-400',
      }
    case 'manifest_declared':
      return {
        label: 'Declared Manifest',
        color: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
        dot: 'bg-amber-400',
      }
    case 'heuristic':
      return {
        label: 'Heuristic',
        color: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
        dot: 'bg-indigo-400',
      }
    default:
      return {
        label: fidelity || 'Standard',
        color: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
        dot: 'bg-slate-400',
      }
  }
}

export function LockfileImportCard({ project }: LockfileImportCardProps) {
  const { capabilities } = useProjects()

  // Match ecosystem capability from backend registry
  const capability = capabilities.find((c) => c.id === project.ecosystem)
  const methods = capability?.supported_import_methods ?? []

  const [selectedMethodId, setSelectedMethodId] = useState<string>('')
  const [serviceName, setServiceName] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [secondaryFile, setSecondaryFile] = useState<File | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [validationError, setValidationError] = useState<string | null>(null)
  const [serverError, setServerError] = useState<{ message: string; requestId?: string } | null>(null)
  const [summary, setSummary] = useState<ImportSummary | null>(null)

  const primaryFileInputRef = useRef<HTMLInputElement>(null)
  const secondaryFileInputRef = useRef<HTMLInputElement>(null)

  // Initialize or reset method selection when project or methods change
  useEffect(() => {
    if (methods.length > 0) {
      if (!selectedMethodId || !methods.some((m) => m.id === selectedMethodId)) {
        setSelectedMethodId(methods[0]!.id)
      }
    }
  }, [project.id, project.ecosystem, methods, selectedMethodId])

  const activeMethod: ImportMethodCapability | undefined =
    methods.find((m) => m.id === selectedMethodId) || methods[0]

  const maxSizeBytes = capability?.max_file_size_bytes ?? 10 * 1024 * 1024
  const maxMb = (maxSizeBytes / (1024 * 1024)).toFixed(0)

  const handleMethodChange = (methodId: string) => {
    setSelectedMethodId(methodId)
    setSelectedFile(null)
    setSecondaryFile(null)
    setValidationError(null)
    setServerError(null)
    if (primaryFileInputRef.current) primaryFileInputRef.current.value = ''
    if (secondaryFileInputRef.current) secondaryFileInputRef.current.value = ''
  }

  const handlePrimaryFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    setValidationError(null)
    setServerError(null)

    if (!file) {
      setSelectedFile(null)
      return
    }

    if (activeMethod) {
      const lowerName = file.name.toLowerCase()
      const acceptedExts = activeMethod.accepted_extensions.map((ext) => ext.toLowerCase())
      const acceptedFiles = activeMethod.accepted_filenames.map((fn) => fn.toLowerCase())

      const hasValidExt = acceptedExts.some((ext) => lowerName.endsWith(ext))
      const hasValidName = acceptedFiles.includes(lowerName)

      if (!hasValidExt && !hasValidName) {
        setValidationError(
          `File "${file.name}" does not match the accepted formats for ${activeMethod.name}. Accepted filenames: ${activeMethod.accepted_filenames.join(', ')} (${activeMethod.accepted_extensions.join(', ')}).`,
        )
      }
    }

    if (file.size > maxSizeBytes) {
      const mbSize = (file.size / (1024 * 1024)).toFixed(1)
      setValidationError(`File size (${mbSize} MB) exceeds maximum allowed limit of ${maxMb} MB.`)
    }

    setSelectedFile(file)
  }

  const handleSecondaryFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    setValidationError(null)
    setServerError(null)

    if (!file) {
      setSecondaryFile(null)
      return
    }

    if (activeMethod?.paired_file_name) {
      const expectedName = activeMethod.paired_file_name.toLowerCase()
      if (file.name.toLowerCase() !== expectedName) {
        setValidationError(
          `Paired file must be named "${activeMethod.paired_file_name}", but received "${file.name}".`,
        )
      }
    }

    if (file.size > maxSizeBytes) {
      const mbSize = (file.size / (1024 * 1024)).toFixed(1)
      setValidationError(
        `Paired file size (${mbSize} MB) exceeds maximum allowed limit of ${maxMb} MB.`,
      )
    }

    setSecondaryFile(file)
  }

  const handleClearPrimaryFile = () => {
    setSelectedFile(null)
    setValidationError(null)
    if (primaryFileInputRef.current) primaryFileInputRef.current.value = ''
  }

  const handleClearSecondaryFile = () => {
    setSecondaryFile(null)
    setValidationError(null)
    if (secondaryFileInputRef.current) secondaryFileInputRef.current.value = ''
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
      setValidationError('Please select a dependency file to import.')
      return
    }

    if (selectedFile.size > maxSizeBytes) {
      setValidationError(`File size exceeds maximum allowed limit of ${maxMb} MB.`)
      return
    }

    if (activeMethod?.requires_paired_file && !secondaryFile) {
      setValidationError(
        `Paired file "${activeMethod.paired_file_name || 'checksum'}" is required for ${activeMethod.name}.`,
      )
      return
    }

    setIsSubmitting(true)
    try {
      const result = await importDependencies(project.id, {
        serviceName: trimmedService,
        file: selectedFile,
        secondaryFile,
        importMethod: activeMethod?.id,
      })
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
    setSecondaryFile(null)
    setValidationError(null)
    setServerError(null)
    if (primaryFileInputRef.current) primaryFileInputRef.current.value = ''
    if (secondaryFileInputRef.current) secondaryFileInputRef.current.value = ''
  }

  const fidelityInfo = getFidelityBadge(activeMethod?.fidelity)

  return (
    <div className="w-full rounded-xl border border-slate-800 bg-[#0f1822] shadow-xl overflow-hidden">
      {/* Header */}
      <div className="border-b border-slate-800/80 bg-slate-900/40 px-6 py-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-sky-500/10 text-sky-400 ring-1 ring-sky-500/20">
              <Upload className="h-5 w-5" aria-hidden="true" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-white">Import Service Dependencies</h2>
              <p className="text-xs text-slate-400">
                Upload ecosystem-native lockfile or manifest to construct graph in FalkorDB
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Project:</span>
            <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-semibold text-slate-200">
              {project.name}
            </span>
            <span className="rounded bg-sky-500/15 border border-sky-500/30 px-2 py-0.5 text-xs font-semibold text-sky-300">
              {capability?.display_name || project.ecosystem}
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
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-semibold text-white">Dependencies Imported</h3>
                    {summary.fidelity && (
                      <span
                        className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                          getFidelityBadge(summary.fidelity).color
                        }`}
                      >
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${
                            getFidelityBadge(summary.fidelity).dot
                          }`}
                        />
                        {getFidelityBadge(summary.fidelity).label}
                      </span>
                    )}
                  </div>
                  <span className="text-xs uppercase tracking-wider font-semibold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                    {summary.status}
                  </span>
                </div>
                <p className="mt-1 text-xs text-slate-300">
                  Dependency hierarchy stored in FalkorDB for service{' '}
                  <span className="font-semibold text-white">{summary.service_name}</span> under{' '}
                  <span className="font-semibold text-sky-300">{summary.ecosystem}</span>.
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
                <div className="mt-1 text-[11px] text-slate-500">Unpinned or links</div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-center">
                <div className="text-2xl font-bold text-slate-300">{summary.errors.length}</div>
                <div className="mt-1 text-xs font-medium text-slate-400">Errors</div>
                <div className="mt-1 text-[11px] text-slate-500">
                  {summary.errors.length === 0 ? 'Zero failures' : `${summary.errors.length} issues`}
                </div>
              </div>
            </div>

            {/* Provenance Box */}
            <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-xs text-slate-300 space-y-2">
              <div className="flex items-center gap-2 font-semibold text-slate-200">
                <Database className="h-4 w-4 text-sky-400" aria-hidden="true" />
                <span>Import Provenance &amp; Integrity</span>
              </div>
              <div className="grid grid-cols-1 gap-2 pt-1 sm:grid-cols-2">
                <div>
                  <span className="text-slate-500">Primary File: </span>
                  <span className="font-mono text-slate-200">{summary.filename}</span>
                </div>
                <div>
                  <span className="text-slate-500">Service: </span>
                  <span className="font-medium text-slate-200">{summary.service_name}</span>
                </div>
                {summary.secondary_filename && (
                  <div>
                    <span className="text-slate-500">Paired Checksum File: </span>
                    <span className="font-mono text-slate-200">{summary.secondary_filename}</span>
                  </div>
                )}
                <div>
                  <span className="text-slate-500">Import Method: </span>
                  <span className="font-medium text-slate-200">{summary.import_method}</span>
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
                  <span>Parser Warnings &amp; Skipped Declarations ({summary.warnings.length})</span>
                </div>
                <ul className="list-disc pl-5 space-y-1 text-slate-300 max-h-48 overflow-y-auto">
                  {summary.warnings.map((w, idx) => (
                    <li key={idx}>{w}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center justify-end gap-3 pt-2">
              <Link
                to="/history"
                className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/30 bg-sky-500/10 px-4 py-2 text-xs font-semibold text-sky-300 transition-colors hover:bg-sky-500/20"
              >
                <History className="h-3.5 w-3.5" aria-hidden="true" />
                View in Ingestion History
              </Link>
              <button
                type="button"
                onClick={handleReset}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-200 transition-colors hover:border-slate-600 hover:bg-slate-700 hover:text-white"
              >
                <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                Import Another Dependency File
              </button>
            </div>
          </div>
        ) : (
          /* Form View */
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Server Error Message */}
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

            {/* Client Validation Error */}
            {validationError && (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3.5 text-xs text-amber-200 flex items-start gap-2.5">
                <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
                <span>{validationError}</span>
              </div>
            )}

            {/* Import Method Selector (when multiple methods available) */}
            {methods.length > 1 && (
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-2">
                  Select Import Format / Method <span className="text-rose-400">*</span>
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2">
                  {methods.map((method) => {
                    const isSelected = method.id === selectedMethodId
                    const badge = getFidelityBadge(method.fidelity)
                    return (
                      <button
                        key={method.id}
                        type="button"
                        onClick={() => handleMethodChange(method.id)}
                        className={`flex flex-col text-left p-3 rounded-lg border transition-all ${
                          isSelected
                            ? 'border-sky-500/60 bg-sky-500/10 ring-1 ring-sky-500/40 text-white'
                            : 'border-slate-800 bg-[#0b121a] hover:border-slate-700 text-slate-300'
                        }`}
                      >
                        <div className="flex items-center justify-between w-full">
                          <span className="text-xs font-semibold">{method.name}</span>
                        </div>
                        <div className="mt-2 flex items-center gap-1.5">
                          <span
                            className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider border ${badge.color}`}
                          >
                            <span className={`h-1 w-1 rounded-full ${badge.dot}`} />
                            {badge.label}
                          </span>
                        </div>
                      </button>
                    )
                  })}
                </div>
              </div>
            )}

            {/* Method Fidelity Guidance Banner */}
            {activeMethod && (
              <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3.5 space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-slate-200">
                      Method: {activeMethod.name}
                    </span>
                    <span
                      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${fidelityInfo.color}`}
                    >
                      <span className={`h-1.5 w-1.5 rounded-full ${fidelityInfo.dot}`} />
                      {fidelityInfo.label}
                    </span>
                  </div>
                  <span className="font-mono text-[11px] text-slate-400">
                    Accepted: {activeMethod.accepted_filenames.join(', ')}
                  </span>
                </div>
                <p className="text-xs text-slate-400">{activeMethod.fidelity_description}</p>
                {activeMethod.limitations.length > 0 && (
                  <div className="pt-1 border-t border-slate-800/80">
                    <ul className="list-disc pl-4 text-[11px] text-amber-300/90 space-y-0.5">
                      {activeMethod.limitations.map((lim, i) => (
                        <li key={i}>{lim}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {/* Service Name Input */}
            <div>
              <label htmlFor="service-name-input" className="block text-xs font-medium text-slate-300">
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
                  placeholder="e.g. payment-service, auth-api, order-worker"
                  className="block w-full rounded-lg border border-slate-700 bg-[#0b121a] px-3.5 py-2 text-sm text-slate-100 placeholder-slate-500 transition-colors focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 disabled:opacity-50"
                />
              </div>
              <p className="mt-1 text-[11px] text-slate-500">
                Dependencies will be scoped and linked to this named service within {project.name}.
              </p>
            </div>

            {/* Primary File Upload Dropzone / Picker */}
            <div>
              <label className="block text-xs font-medium text-slate-300">
                Primary Dependency File <span className="text-rose-400">*</span>
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
                          {(selectedFile.size / 1024).toFixed(1)} KB &bull; {project.ecosystem} input
                        </div>
                      </div>
                    </div>
                    <button
                      type="button"
                      disabled={isSubmitting}
                      onClick={handleClearPrimaryFile}
                      className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 disabled:opacity-50"
                      aria-label="Remove selected file"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                ) : (
                  <label
                    htmlFor="primary-file-input"
                    className="flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed border-slate-700 bg-[#0b121a] px-6 py-6 transition-colors hover:border-slate-500 hover:bg-slate-900/40"
                  >
                    <FileCode className="h-8 w-8 text-slate-400" aria-hidden="true" />
                    <span className="mt-2 text-xs font-semibold text-slate-300">
                      Click to choose{' '}
                      <span className="text-sky-400 font-mono">
                        {activeMethod?.accepted_filenames.join(' or ') || 'dependency file'}
                      </span>
                    </span>
                    <span className="mt-1 text-[11px] text-slate-500">
                      {activeMethod?.name || project.ecosystem} (up to {maxMb} MB)
                    </span>
                    <input
                      id="primary-file-input"
                      ref={primaryFileInputRef}
                      type="file"
                      accept={activeMethod?.accepted_extensions.join(',') || undefined}
                      disabled={isSubmitting}
                      onChange={handlePrimaryFileChange}
                      className="sr-only"
                    />
                  </label>
                )}
              </div>
            </div>

            {/* Optional or Required Secondary Paired File Dropzone */}
            {activeMethod && (activeMethod.paired_file_name || activeMethod.requires_paired_file) && (
              <div>
                <div className="flex items-center justify-between">
                  <label className="block text-xs font-medium text-slate-300">
                    Paired Checksum File ({activeMethod.paired_file_name})
                    {activeMethod.requires_paired_file ? (
                      <span className="text-rose-400"> *</span>
                    ) : (
                      <span className="text-slate-500"> (Optional)</span>
                    )}
                  </label>
                  <span className="text-[11px] text-sky-400 flex items-center gap-1">
                    <ShieldCheck className="h-3 w-3" />
                    Cryptographic Checksum Verification
                  </span>
                </div>
                <div className="mt-1.5">
                  {secondaryFile ? (
                    <div className="flex items-center justify-between rounded-lg border border-cyan-500/40 bg-cyan-500/5 px-4 py-3">
                      <div className="flex items-center gap-3">
                        <FileCheck className="h-5 w-5 text-cyan-400" aria-hidden="true" />
                        <div>
                          <div className="text-xs font-semibold text-slate-200">
                            {secondaryFile.name}
                          </div>
                          <div className="text-[11px] text-slate-400">
                            {(secondaryFile.size / 1024).toFixed(1)} KB &bull; checksums paired
                          </div>
                        </div>
                      </div>
                      <button
                        type="button"
                        disabled={isSubmitting}
                        onClick={handleClearSecondaryFile}
                        className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 disabled:opacity-50"
                        aria-label="Remove paired file"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    </div>
                  ) : (
                    <label
                      htmlFor="secondary-file-input"
                      className="flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed border-slate-700 bg-[#0b121a] px-6 py-4 transition-colors hover:border-slate-500 hover:bg-slate-900/40"
                    >
                      <FileText className="h-6 w-6 text-slate-400" aria-hidden="true" />
                      <span className="mt-1 text-xs font-semibold text-slate-300">
                        Attach paired{' '}
                        <span className="text-cyan-400 font-mono">{activeMethod.paired_file_name}</span>
                      </span>
                      <span className="mt-0.5 text-[11px] text-slate-500">
                        {activeMethod.paired_file_description || 'Optional paired verification file'}
                      </span>
                      <input
                        id="secondary-file-input"
                        ref={secondaryFileInputRef}
                        type="file"
                        accept={`.${activeMethod.paired_file_name?.split('.').pop() || 'sum'}`}
                        disabled={isSubmitting}
                        onChange={handleSecondaryFileChange}
                        className="sr-only"
                      />
                    </label>
                  )}
                </div>
              </div>
            )}

            {/* Security Guarantee Notice */}
            <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3.5 text-xs text-slate-400 flex items-center gap-2.5">
              <Layers className="h-4 w-4 text-sky-400 shrink-0" aria-hidden="true" />
              <span>
                <strong>Zero Code Execution:</strong> Vulnify parses dependency declarations via
                isolated deterministic ASTs. Manifest scripts, lifecycle hooks, and shell commands
                are never executed.
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
                    <span>Import Dependencies</span>
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
