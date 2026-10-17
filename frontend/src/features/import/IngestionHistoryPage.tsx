import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import {
  History,
  RotateCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2,
  Upload,
  ShieldAlert,
  Cpu,
  Eye,
  Copy,
  Check,
  Filter,
  X,
  ChevronLeft,
  ChevronRight,
  Database,
  RotateCcw,
  AlertCircle,
  Clock,
} from 'lucide-react'
import { useProjects } from '@/features/projects/ProjectProvider'
import {
  listIngestionJobs,
  retryIngestionJob,
  ProjectApiError,
} from '@/features/projects/projectApi'
import type {
  IngestionJob,
  IngestionJobSummaryStats,
} from '@/features/projects/types'

function formatRelativeTime(ts: number): string {
  const diffSec = Math.floor(Date.now() / 1000) - ts
  if (diffSec < 60) return `${Math.max(1, diffSec)}s ago`
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin}m ago`
  const diffHour = Math.floor(diffMin / 60)
  if (diffHour < 24) return `${diffHour}h ago`
  const diffDay = Math.floor(diffHour / 24)
  return `${diffDay}d ago`
}

function formatDuration(ms?: number | null): string {
  if (ms === undefined || ms === null) return '—'
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toFixed(2)} s`
}

export function IngestionHistoryPage() {
  const { activeProject } = useProjects()

  const [jobs, setJobs] = useState<IngestionJob[]>([])
  const [summaryStats, setSummaryStats] = useState<IngestionJobSummaryStats | null>(null)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize] = useState(15)
  const [totalPages, setTotalPages] = useState(1)

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [serviceSearch, setServiceSearch] = useState<string>('')

  // State
  const [isLoading, setIsLoading] = useState<boolean>(true)
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date())

  // Drawer / Details Modal
  const [selectedJob, setSelectedJob] = useState<IngestionJob | null>(null)
  const [isCopied, setIsCopied] = useState<boolean>(false)

  // Retry state
  const [isRetrying, setIsRetrying] = useState<boolean>(false)
  const [retryFeedback, setRetryFeedback] = useState<{
    success: boolean
    message: string
  } | null>(null)

  // Fetch jobs
  const fetchJobs = useCallback(
    async (isBackground = false) => {
      if (!activeProject) return

      if (isBackground) {
        setIsRefreshing(true)
      } else {
        setIsLoading(true)
      }
      setError(null)

      try {
        const response = await listIngestionJobs(activeProject.id, {
          page,
          page_size: pageSize,
          status: statusFilter !== 'all' ? statusFilter : undefined,
          job_type: typeFilter !== 'all' ? typeFilter : undefined,
          service_name: serviceSearch.trim() || undefined,
        })

        setJobs(response.items)
        setTotal(response.total)
        setTotalPages(response.total_pages)
        setSummaryStats(response.summary_stats)
        setLastUpdated(new Date())

        // If inspecting a job that updated in the background, sync it safely
        setSelectedJob((current) => {
          if (!current) return null
          const updated = response.items.find((j) => j.id === current.id)
          return updated ?? current
        })
      } catch (err) {
        if (err instanceof ProjectApiError) {
          setError(err.message)
        } else {
          setError('Failed to retrieve ingestion jobs from server.')
        }
      } finally {
        setIsLoading(false)
        setIsRefreshing(false)
      }
    },
    [activeProject, page, pageSize, statusFilter, typeFilter, serviceSearch],
  )

  // Initial and reactive fetch on project or filter change
  useEffect(() => {
    fetchJobs()
  }, [fetchJobs])

  // Modal close handler
  const handleCloseModal = useCallback(() => {
    setSelectedJob(null)
    setRetryFeedback(null)
    setIsCopied(false)
  }, [])

  // Close modal on Escape key press
  useEffect(() => {
    if (!selectedJob) return
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        handleCloseModal()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [selectedJob, handleCloseModal])

  // Check if active (running or queued) jobs exist
  const hasActiveJobs = useMemo(() => {
    return jobs.some((j) => j.status === 'running' || j.status === 'queued')
  }, [jobs])

  // Live polling: poll every 3 seconds while active jobs exist
  useEffect(() => {
    if (!hasActiveJobs || !activeProject) return

    const timer = setInterval(() => {
      fetchJobs(true)
    }, 3000)

    return () => clearInterval(timer)
  }, [hasActiveJobs, activeProject, fetchJobs])

  // Copy hash helper
  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash)
    setIsCopied(true)
    setTimeout(() => setIsCopied(false), 2000)
  }

  // Handle retry
  const handleRetry = async (job: IngestionJob) => {
    if (!activeProject) return
    setIsRetrying(true)
    setRetryFeedback(null)

    try {
      const result = await retryIngestionJob(activeProject.id, job.id)
      setRetryFeedback({
        success: true,
        message: result.message || 'Job retried successfully.',
      })
      // Refresh list
      await fetchJobs(true)
      setSelectedJob(result.new_job)
    } catch (err) {
      const msg =
        err instanceof ProjectApiError
          ? err.message
          : 'Failed to trigger job retry.'
      setRetryFeedback({
        success: false,
        message: msg,
      })
    } finally {
      setIsRetrying(false)
    }
  }

  const handleClearFilters = () => {
    setStatusFilter('all')
    setTypeFilter('all')
    setServiceSearch('')
    setPage(1)
  }

  if (!activeProject) {
    return (
      <div className="rounded-xl border border-dashed border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
        <AlertCircle className="mx-auto h-8 w-8 text-amber-400" aria-hidden="true" />
        <h2 className="mt-3 text-sm font-bold text-white">No Active Project Selected</h2>
        <p className="mt-1 text-slate-400">
          Please select or create a project in the top navigation bar to view its ingestion history.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-white">Ingestion History &amp; Audit Log</h1>
            <span className="rounded-full bg-sky-500/15 border border-sky-500/30 px-2.5 py-0.5 text-[10px] font-semibold text-sky-300">
              {activeProject.name} &bull; {activeProject.ecosystem}
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Persistent audit record of dependency imports, OSV advisory syncs, SHA-256 hashes, and version matching runs.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {hasActiveJobs && (
            <div className="flex items-center gap-2 rounded-lg border border-sky-500/30 bg-sky-500/10 px-3 py-1.5 text-xs text-sky-300">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sky-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-sky-500" />
              </span>
              <span>Live polling active</span>
            </div>
          )}

          <button
            type="button"
            onClick={() => fetchJobs(true)}
            disabled={isRefreshing || isLoading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-200 transition-colors hover:border-slate-600 hover:bg-slate-700 hover:text-white disabled:opacity-50"
            title={`Last refreshed at ${lastUpdated.toLocaleTimeString()}`}
          >
            <RotateCw
              className={`h-3.5 w-3.5 ${isRefreshing ? 'animate-spin text-sky-400' : 'text-slate-400'}`}
              aria-hidden="true"
            />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Metrics Bar */}
      {summaryStats && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Total Runs</span>
              <Database className="h-4 w-4 text-sky-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-white">{summaryStats.total_runs}</div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">In Progress</span>
              <Loader2 className={`h-4 w-4 ${summaryStats.running_runs > 0 ? 'text-sky-400 animate-spin' : 'text-slate-500'}`} />
            </div>
            <div className="mt-2 text-2xl font-bold text-sky-400">{summaryStats.running_runs}</div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Succeeded</span>
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-emerald-400">{summaryStats.succeeded_runs}</div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Partial / Warnings</span>
              <AlertTriangle className="h-4 w-4 text-amber-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-amber-400">{summaryStats.partial_runs}</div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Failed</span>
              <XCircle className="h-4 w-4 text-rose-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-rose-400">{summaryStats.failed_runs}</div>
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Filter className="h-3.5 w-3.5 text-slate-400" />
              <span>Filters:</span>
            </div>

            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value)
                setPage(1)
              }}
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
            >
              <option value="all">All Statuses</option>
              <option value="queued">Queued</option>
              <option value="running">Running</option>
              <option value="succeeded">Succeeded</option>
              <option value="partial">Partial</option>
              <option value="failed">Failed</option>
            </select>

            {/* Job Type Filter */}
            <select
              value={typeFilter}
              onChange={(e) => {
                setTypeFilter(e.target.value)
                setPage(1)
              }}
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
            >
              <option value="all">All Types</option>
              <option value="dependency_import">Dependency Import</option>
              <option value="osv_sync">OSV Advisory Sync</option>
              <option value="version_matching">Version Matching</option>
            </select>

            {/* Service Name Search */}
            <div className="relative">
              <input
                type="text"
                placeholder="Search service name..."
                value={serviceSearch}
                onChange={(e) => {
                  setServiceSearch(e.target.value)
                  setPage(1)
                }}
                className="w-48 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
              />
              {serviceSearch && (
                <button
                  type="button"
                  onClick={() => {
                    setServiceSearch('')
                    setPage(1)
                  }}
                  className="absolute right-2 top-2 text-slate-400 hover:text-white"
                >
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>
          </div>

          {(statusFilter !== 'all' || typeFilter !== 'all' || serviceSearch.trim()) && (
            <button
              type="button"
              onClick={handleClearFilters}
              className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-white"
            >
              <X className="h-3.5 w-3.5" />
              <span>Reset Filters</span>
            </button>
          )}
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-200 flex items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            type="button"
            onClick={() => fetchJobs()}
            className="text-xs font-semibold text-rose-300 underline hover:text-rose-100"
          >
            Retry
          </button>
        </div>
      )}

      {/* Table Content */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] shadow-xl overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center text-xs text-slate-400">
            <Loader2 className="mx-auto h-8 w-8 animate-spin text-sky-400" />
            <p className="mt-3 font-semibold text-white">Loading Ingestion History...</p>
            <p className="mt-1 text-slate-500">Querying persistent graph runs in FalkorDB</p>
          </div>
        ) : jobs.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-400">
            <History className="mx-auto h-8 w-8 text-slate-600" />
            <h3 className="mt-3 text-sm font-semibold text-white">
              {statusFilter !== 'all' || typeFilter !== 'all' || serviceSearch.trim()
                ? 'No Ingestion Runs Match Filters'
                : 'No Ingestion Runs Recorded Yet'}
            </h3>
            <p className="mt-1 text-slate-400 max-w-sm mx-auto">
              {statusFilter !== 'all' || typeFilter !== 'all' || serviceSearch.trim()
                ? 'Try resetting your filter parameters or search terms.'
                : 'Import dependency lockfiles or sync OSV security advisories to record persistent ingestion history.'}
            </p>
            <div className="mt-4 flex items-center justify-center gap-3">
              {statusFilter !== 'all' || typeFilter !== 'all' || serviceSearch.trim() ? (
                <button
                  type="button"
                  onClick={handleClearFilters}
                  className="rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-1.5 text-xs font-semibold text-slate-200 hover:bg-slate-700"
                >
                  Clear Filters
                </button>
              ) : (
                <Link
                  to="/import"
                  className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-sky-400"
                >
                  <Upload className="h-3.5 w-3.5" />
                  <span>Go to Import Data</span>
                </Link>
              )}
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-slate-800 bg-slate-900/60 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                <tr>
                  <th scope="col" className="px-4 py-3">Status</th>
                  <th scope="col" className="px-4 py-3">Type &amp; Service</th>
                  <th scope="col" className="px-4 py-3">Stage / Progress</th>
                  <th scope="col" className="px-4 py-3">Graph Changes</th>
                  <th scope="col" className="px-4 py-3">Duration &amp; Age</th>
                  <th scope="col" className="px-4 py-3">Operator</th>
                  <th scope="col" className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {jobs.map((job) => (
                  <tr
                    key={job.id}
                    className="hover:bg-slate-800/30 transition-colors"
                  >
                    {/* Status badge */}
                    <td className="px-4 py-3.5 whitespace-nowrap">
                      {job.status === 'succeeded' ? (
                        <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-300">
                          <CheckCircle2 className="h-3 w-3" />
                          <span>Succeeded</span>
                        </span>
                      ) : job.status === 'partial' ? (
                        <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/15 border border-amber-500/30 px-2.5 py-0.5 text-[11px] font-semibold text-amber-300">
                          <AlertTriangle className="h-3 w-3" />
                          <span>Partial</span>
                        </span>
                      ) : job.status === 'failed' ? (
                        <span className="inline-flex items-center gap-1.5 rounded-full bg-rose-500/15 border border-rose-500/30 px-2.5 py-0.5 text-[11px] font-semibold text-rose-300">
                          <XCircle className="h-3 w-3" />
                          <span>Failed</span>
                        </span>
                      ) : job.status === 'running' ? (
                        <span className="inline-flex items-center gap-1.5 rounded-full bg-sky-500/15 border border-sky-500/30 px-2.5 py-0.5 text-[11px] font-semibold text-sky-300">
                          <Loader2 className="h-3 w-3 animate-spin" />
                          <span>Running</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-700/40 border border-slate-700 px-2.5 py-0.5 text-[11px] font-semibold text-slate-300">
                          <Clock className="h-3 w-3" />
                          <span>Queued</span>
                        </span>
                      )}
                    </td>

                    {/* Type and Service */}
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-2">
                        {job.job_type === 'dependency_import' ? (
                          <Upload className="h-4 w-4 text-sky-400 shrink-0" />
                        ) : job.job_type === 'osv_sync' ? (
                          <ShieldAlert className="h-4 w-4 text-amber-400 shrink-0" />
                        ) : (
                          <Cpu className="h-4 w-4 text-indigo-400 shrink-0" />
                        )}
                        <div>
                          <div className="font-semibold text-white capitalize">
                            {job.job_type.replace('_', ' ')}
                          </div>
                          {job.service_name && (
                            <div className="text-[11px] text-slate-400">
                              Service: <span className="font-mono text-slate-200">{job.service_name}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    </td>

                    {/* Stage & Progress */}
                    <td className="px-4 py-3.5 max-w-xs">
                      <div className="truncate text-slate-200 text-xs" title={job.stage || ''}>
                        {job.stage || '—'}
                      </div>
                      {job.total_items && job.total_items > 0 ? (
                        <div className="mt-1.5">
                          <div className="flex items-center justify-between text-[10px] text-slate-400 mb-0.5">
                            <span>
                              {job.processed_items}/{job.total_items} items
                            </span>
                            <span>{job.percentage ?? Math.round((job.processed_items / job.total_items) * 100)}%</span>
                          </div>
                          <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                            <div
                              className="h-full bg-sky-500 rounded-full transition-all"
                              style={{
                                width: `${Math.min(100, job.percentage ?? Math.round((job.processed_items / job.total_items) * 100))}%`,
                              }}
                            />
                          </div>
                        </div>
                      ) : null}
                    </td>

                    {/* Graph Changes */}
                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <div className="space-y-0.5 text-[11px]">
                        <div>
                          <span className="text-emerald-400 font-semibold">+{job.created_items}</span>
                          <span className="text-slate-500"> created</span>
                        </div>
                        {job.reused_items > 0 && (
                          <div>
                            <span className="text-slate-300 font-semibold">{job.reused_items}</span>
                            <span className="text-slate-500"> reused</span>
                          </div>
                        )}
                        {job.failed_items > 0 && (
                          <div>
                            <span className="text-rose-400 font-semibold">{job.failed_items}</span>
                            <span className="text-slate-500"> failed</span>
                          </div>
                        )}
                      </div>
                    </td>

                    {/* Duration and Timestamp */}
                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <div className="font-mono text-slate-200">{formatDuration(job.duration_ms)}</div>
                      <div
                        className="text-[11px] text-slate-400 cursor-default"
                        title={new Date(job.created_at * 1000).toUTCString()}
                      >
                        {formatRelativeTime(job.created_at)}
                      </div>
                    </td>

                    {/* Operator */}
                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <div className="text-xs text-slate-300 truncate max-w-[140px]" title={job.initiated_by || 'system'}>
                        {job.initiated_by || 'system'}
                      </div>
                      {job.retry_of_job_id && (
                        <div className="text-[10px] text-amber-400 flex items-center gap-1" title={`Retry of job ${job.retry_of_job_id}`}>
                          <RotateCcw className="h-2.5 w-2.5" />
                          <span>Retry run</span>
                        </div>
                      )}
                    </td>

                    {/* Actions */}
                    <td className="px-4 py-3.5 text-right whitespace-nowrap">
                      <div className="inline-flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedJob(job)
                            setRetryFeedback(null)
                          }}
                          className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-semibold text-slate-300 hover:bg-slate-700 hover:text-white"
                          title="View job details"
                        >
                          <Eye className="h-3.5 w-3.5" />
                          <span>Inspect</span>
                        </button>

                        {job.retry_eligible && (job.status === 'failed' || job.status === 'partial') && (
                          <button
                            type="button"
                            onClick={() => handleRetry(job)}
                            disabled={isRetrying}
                            className="inline-flex items-center gap-1 rounded-md border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-xs font-semibold text-amber-300 hover:bg-amber-500/20 disabled:opacity-50"
                            title="Retry job"
                          >
                            <RotateCcw className={`h-3 w-3 ${isRetrying ? 'animate-spin' : ''}`} />
                            <span>Retry</span>
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {jobs.length > 0 && (
          <div className="border-t border-slate-800 bg-slate-900/40 px-4 py-3 flex items-center justify-between text-xs text-slate-400">
            <div>
              Showing <span className="text-white font-medium">{(page - 1) * pageSize + 1}</span> to{' '}
              <span className="text-white font-medium">{Math.min(page * pageSize, total)}</span> of{' '}
              <span className="text-white font-medium">{total}</span> runs
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
                <span>Prev</span>
              </button>

              <span className="px-2 text-slate-400">
                Page <span className="font-semibold text-white">{page}</span> of{' '}
                <span className="font-semibold text-white">{totalPages}</span>
              </span>

              <button
                type="button"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <span>Next</span>
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Job Details Modal / Drawer */}
      {selectedJob && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
          onClick={handleCloseModal}
          role="dialog"
          aria-modal="true"
        >
          <div
            className="w-full max-w-2xl rounded-xl border border-slate-700 bg-[#0f1822] shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="border-b border-slate-800 bg-slate-900/60 px-6 py-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-500/10 text-sky-400 ring-1 ring-sky-500/20">
                  {selectedJob.job_type === 'dependency_import' ? (
                    <Upload className="h-5 w-5" />
                  ) : selectedJob.job_type === 'osv_sync' ? (
                    <ShieldAlert className="h-5 w-5 text-amber-400" />
                  ) : (
                    <Cpu className="h-5 w-5 text-indigo-400" />
                  )}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-base font-semibold text-white capitalize">
                      {selectedJob.job_type.replace('_', ' ')} Run
                    </h2>
                    <span
                      className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ${
                        selectedJob.status === 'succeeded'
                          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                          : selectedJob.status === 'partial'
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                            : selectedJob.status === 'failed'
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                              : 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                      }`}
                    >
                      {selectedJob.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 font-mono mt-0.5 truncate max-w-md">
                    Job ID: {selectedJob.id}
                  </p>
                </div>
              </div>

              <button
                type="button"
                onClick={handleCloseModal}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors focus:outline-none focus:ring-2 focus:ring-sky-500"
                aria-label="Close modal"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-5 overflow-y-auto">
              {/* Retry feedback alert */}
              {retryFeedback && (
                <div
                  className={`rounded-lg p-3 text-xs flex items-center gap-2 ${
                    retryFeedback.success
                      ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
                      : 'bg-rose-500/10 border border-rose-500/30 text-rose-300'
                  }`}
                >
                  {retryFeedback.success ? (
                    <CheckCircle2 className="h-4 w-4 shrink-0" />
                  ) : (
                    <AlertCircle className="h-4 w-4 shrink-0" />
                  )}
                  <span>{retryFeedback.message}</span>
                </div>
              )}

              {/* Execution Summary Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 text-center">
                  <div className="text-lg font-bold text-white">{selectedJob.processed_items}</div>
                  <div className="text-[11px] text-slate-400">Processed Items</div>
                </div>

                <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 text-center">
                  <div className="text-lg font-bold text-emerald-400">{selectedJob.created_items}</div>
                  <div className="text-[11px] text-slate-400">Created Nodes</div>
                </div>

                <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 text-center">
                  <div className="text-lg font-bold text-sky-400">{selectedJob.reused_items}</div>
                  <div className="text-[11px] text-slate-400">Reused Nodes</div>
                </div>

                <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 text-center">
                  <div className="text-lg font-bold text-slate-300">{formatDuration(selectedJob.duration_ms)}</div>
                  <div className="text-[11px] text-slate-400">Execution Time</div>
                </div>
              </div>

              {/* Provenance & File Metadata */}
              {(selectedJob.filename || selectedJob.sha256_hash || selectedJob.ecosystem) && (
                <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-xs space-y-3">
                  <div className="flex items-center gap-2 font-semibold text-slate-200">
                    <Database className="h-4 w-4 text-sky-400" />
                    <span>File Provenance &amp; Integrity</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-300">
                    {selectedJob.filename && (
                      <div>
                        <span className="text-slate-500">File: </span>
                        <span className="font-mono text-slate-200">{selectedJob.filename}</span>
                      </div>
                    )}
                    {selectedJob.secondary_filename && (
                      <div>
                        <span className="text-slate-500">Paired File: </span>
                        <span className="font-mono text-slate-200">{selectedJob.secondary_filename}</span>
                      </div>
                    )}
                    {selectedJob.service_name && (
                      <div>
                        <span className="text-slate-500">Service: </span>
                        <span className="font-medium text-slate-200">{selectedJob.service_name}</span>
                      </div>
                    )}
                    {selectedJob.ecosystem && (
                      <div>
                        <span className="text-slate-500">Ecosystem: </span>
                        <span className="font-semibold text-sky-300">{selectedJob.ecosystem}</span>
                      </div>
                    )}
                    {selectedJob.import_method && (
                      <div>
                        <span className="text-slate-500">Method: </span>
                        <span className="font-mono text-slate-200">{selectedJob.import_method}</span>
                      </div>
                    )}
                    {selectedJob.fidelity && (
                      <div>
                        <span className="text-slate-500">Fidelity: </span>
                        <span className="font-semibold text-cyan-300">{selectedJob.fidelity}</span>
                      </div>
                    )}
                  </div>

                  {selectedJob.sha256_hash && (
                    <div className="pt-2 border-t border-slate-800/80">
                      <div className="flex items-center justify-between text-slate-500 mb-1">
                        <span>Primary SHA-256 Digest:</span>
                        <button
                          type="button"
                          onClick={() => handleCopyHash(selectedJob.sha256_hash || '')}
                          className="inline-flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300"
                        >
                          {isCopied ? (
                            <>
                              <Check className="h-3 w-3 text-emerald-400" />
                              <span className="text-emerald-400">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="h-3 w-3" />
                              <span>Copy Digest</span>
                            </>
                          )}
                        </button>
                      </div>
                      <div className="rounded bg-slate-900 p-2 font-mono text-[11px] text-slate-300 break-all border border-slate-800">
                        {selectedJob.sha256_hash}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Execution Details & Timestamps */}
              <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-xs space-y-2">
                <div className="flex items-center gap-2 font-semibold text-slate-200">
                  <Clock className="h-4 w-4 text-sky-400" />
                  <span>Execution Timeline</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-300">
                  <div>
                    <span className="text-slate-500">Created: </span>
                    <span>{new Date(selectedJob.created_at * 1000).toUTCString()}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Started: </span>
                    <span>
                      {selectedJob.started_at
                        ? new Date(selectedJob.started_at * 1000).toUTCString()
                        : '—'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500">Completed: </span>
                    <span>
                      {selectedJob.completed_at
                        ? new Date(selectedJob.completed_at * 1000).toUTCString()
                        : '—'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500">Initiated By: </span>
                    <span className="font-medium text-slate-200">{selectedJob.initiated_by || 'system'}</span>
                  </div>
                  {selectedJob.retry_of_job_id && (
                    <div className="sm:col-span-2 pt-1">
                      <span className="text-slate-500">Retry Of Run: </span>
                      <span className="font-mono text-amber-300 text-[11px]">{selectedJob.retry_of_job_id}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Errors Section */}
              {(selectedJob.error_summary || selectedJob.errors.length > 0) && (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-200 space-y-2">
                  <div className="flex items-center gap-2 font-semibold text-rose-300">
                    <XCircle className="h-4 w-4 shrink-0 text-rose-400" />
                    <span>Failure Summary</span>
                  </div>
                  {selectedJob.error_summary && <p className="font-medium">{selectedJob.error_summary}</p>}
                  {selectedJob.errors.length > 0 && (
                    <ul className="list-disc pl-5 space-y-1 text-slate-300">
                      {selectedJob.errors.map((err, idx) => (
                        <li key={idx}>{err}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* Warnings Section */}
              {selectedJob.warnings.length > 0 && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-200 space-y-2">
                  <div className="flex items-center gap-2 font-semibold text-amber-300">
                    <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
                    <span>Non-Fatal Warnings ({selectedJob.warnings.length})</span>
                  </div>
                  <ul className="list-disc pl-5 space-y-1 text-slate-300 max-h-36 overflow-y-auto">
                    {selectedJob.warnings.map((w, idx) => (
                      <li key={idx}>{w}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="border-t border-slate-800 bg-slate-900/60 px-6 py-3 flex items-center justify-between">
              <div>
                {selectedJob.retry_eligible && (selectedJob.status === 'failed' || selectedJob.status === 'partial') && (
                  selectedJob.job_type === 'dependency_import' ? (
                    <Link
                      to="/import"
                      className="inline-flex items-center gap-1.5 text-xs text-sky-400 hover:text-sky-300"
                    >
                      <Upload className="h-3.5 w-3.5" />
                      <span>Re-upload lockfile on Import Data page</span>
                    </Link>
                  ) : (
                    <button
                      type="button"
                      onClick={() => handleRetry(selectedJob)}
                      disabled={isRetrying}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/15 px-3 py-1.5 text-xs font-semibold text-amber-300 hover:bg-amber-500/25 disabled:opacity-50"
                    >
                      <RotateCcw className={`h-3.5 w-3.5 ${isRetrying ? 'animate-spin' : ''}`} />
                      <span>Retry Ingestion Run</span>
                    </button>
                  )
                )}
              </div>

              <button
                type="button"
                onClick={handleCloseModal}
                className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-700 hover:text-white transition-colors focus:outline-none focus:ring-2 focus:ring-sky-500"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
