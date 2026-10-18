import { useState, useEffect, useCallback, useId } from 'react'
import {
  Search,
  Filter,
  Loader2,
  RefreshCw,
  AlertCircle,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  Route,
  Clock,
  ChevronLeft,
  ChevronRight,
  X,
  ExternalLink,
  Layers,
  HelpCircle,
} from 'lucide-react'
import { Link, useSearchParams } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import {
  getProjectFindings,
  getProjectFindingsSummary,
  listProjectServices,
  getProjectDataQuality,
} from '@/features/projects/projectApi'
import type {
  FindingListResponse,
  FindingSummaryResponse,
  ProjectService,
  FindingPriority,
  FindingTriageStatus,
  DataQualityWarning,
} from '@/features/projects/types'
import { ProjectApiError } from '@/features/projects/projectApi'
import { DataQualityBanner } from '@/shared/components/DataQualityBanner'

export function FindingsPage() {
  const { activeProject } = useProjects()
  const [searchParams, setSearchParams] = useSearchParams()

  const [findingsData, setFindingsData] = useState<FindingListResponse>({
    items: [],
    page: 1,
    page_size: 25,
    total: 0,
    total_pages: 0,
  })
  const [services, setServices] = useState<ProjectService[]>([])
  const [warnings, setWarnings] = useState<DataQualityWarning[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [errorRequestId, setErrorRequestId] = useState<string | null>(null)

  // Summary cards state
  const [summaryData, setSummaryData] = useState<FindingSummaryResponse | null>(null)
  const [isSummaryLoading, setIsSummaryLoading] = useState(false)
  const [summaryError, setSummaryError] = useState<string | null>(null)

  // URL-persisted search, filter, and pagination parameters
  const pageParam = parseInt(searchParams.get('page') || '1', 10)
  const currentPage = isNaN(pageParam) || pageParam < 1 ? 1 : pageParam
  const priorityFilter = searchParams.get('priority') || 'ALL'
  const serviceFilter = searchParams.get('service_id') || 'ALL'
  const statusFilter = searchParams.get('status') || 'ALL'
  const urlSearchTerm = searchParams.get('search') || searchParams.get('q') || ''

  // Local search state for responsive typing before debouncing to URL
  const [searchInput, setSearchInput] = useState(urlSearchTerm)

  // Unique accessible IDs
  const searchInputId = useId()
  const prioritySelectId = useId()
  const serviceSelectId = useId()
  const statusSelectId = useId()

  // Sync search input when URL search changes externally (e.g. Back/Forward)
  useEffect(() => {
    setSearchInput(urlSearchTerm)
  }, [urlSearchTerm])

  // Debounce search input to URL query parameter
  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchInput !== urlSearchTerm) {
        setSearchParams((prev) => {
          const next = new URLSearchParams(prev)
          if (searchInput.trim()) {
            next.set('search', searchInput.trim())
            next.delete('q') // standardize on 'search'
          } else {
            next.delete('search')
            next.delete('q')
          }
          next.set('page', '1') // resetting to page 1 on search change
          return next
        })
      }
    }, 300)

    return () => clearTimeout(timer)
  }, [searchInput, urlSearchTerm, setSearchParams])

  // Load project services for the service filter dropdown
  useEffect(() => {
    let isMounted = true
    async function fetchServices(projectId: string) {
      try {
        const data = await listProjectServices(projectId)
        if (isMounted) {
          setServices(data)
        }
      } catch {
        // Soft failure: if services list fails, dropdown remains with 'All Services'
        if (isMounted) {
          setServices([])
        }
      }
    }

    if (activeProject) {
      void fetchServices(activeProject.id)
    } else {
      setServices([])
    }

    return () => {
      isMounted = false
    }
  }, [activeProject])

  // Fetch paginated findings from backend
  const loadFindings = useCallback(
    async (projectId: string) => {
      setIsLoading(true)
      setError(null)
      setErrorRequestId(null)

      try {
        const response = await getProjectFindings(projectId, {
          page: currentPage,
          page_size: 25,
          priority: priorityFilter !== 'ALL' ? priorityFilter : undefined,
          service_id: serviceFilter !== 'ALL' ? serviceFilter : undefined,
          status: statusFilter !== 'ALL' ? statusFilter : undefined,
          search: urlSearchTerm.trim() || undefined,
          sort_by: 'priority',
        })
        setFindingsData(response)
      } catch (err) {
        if (err instanceof ProjectApiError) {
          setError(err.message)
          setErrorRequestId(err.requestId || null)
        } else {
          setError('Failed to load project vulnerability findings.')
        }
      } finally {
        setIsLoading(false)
      }
    },
    [currentPage, priorityFilter, serviceFilter, statusFilter, urlSearchTerm],
  )

  // Fetch aggregated findings summary for summary cards
  const loadSummary = useCallback(
    async (projectId: string) => {
      setIsSummaryLoading(true)
      setSummaryError(null)

      try {
        const response = await getProjectFindingsSummary(projectId, {
          priority: priorityFilter !== 'ALL' ? priorityFilter : undefined,
          service_id: serviceFilter !== 'ALL' ? serviceFilter : undefined,
          status: statusFilter !== 'ALL' ? statusFilter : undefined,
          search: urlSearchTerm.trim() || undefined,
        })
        setSummaryData(response)
      } catch (err) {
        if (err instanceof ProjectApiError) {
          setSummaryError(err.message)
        } else {
          setSummaryError('Failed to load findings summary metrics.')
        }
      } finally {
        setIsSummaryLoading(false)
      }
    },
    [priorityFilter, serviceFilter, statusFilter, urlSearchTerm],
  )

  // Fetch project data-quality warnings
  const loadWarnings = useCallback(async (projectId: string) => {
    try {
      const dq = await getProjectDataQuality(projectId)
      setWarnings(dq.warnings || [])
    } catch {
      setWarnings([])
    }
  }, [])

  useEffect(() => {
    if (activeProject) {
      void loadFindings(activeProject.id)
      void loadSummary(activeProject.id)
      void loadWarnings(activeProject.id)
    } else {
      setFindingsData({
        items: [],
        page: 1,
        page_size: 25,
        total: 0,
        total_pages: 0,
      })
      setSummaryData(null)
      setWarnings([])
    }
  }, [activeProject, loadFindings, loadSummary, loadWarnings])

  // Filter change handlers
  const handlePriorityChange = (priority: string) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      if (priority && priority !== 'ALL') {
        next.set('priority', priority)
      } else {
        next.delete('priority')
      }
      next.set('page', '1')
      return next
    })
  }

  const handleServiceChange = (serviceId: string) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      if (serviceId && serviceId !== 'ALL') {
        next.set('service_id', serviceId)
      } else {
        next.delete('service_id')
      }
      next.set('page', '1')
      return next
    })
  }

  const handleStatusChange = (status: string) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      if (status && status !== 'ALL') {
        next.set('status', status)
      } else {
        next.delete('status')
      }
      next.set('page', '1')
      return next
    })
  }

  const handlePageChange = (newPage: number) => {
    if (newPage < 1 || newPage > (findingsData.total_pages || 1)) return
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.set('page', String(newPage))
      return next
    })
  }

  const handleClearFilters = () => {
    setSearchInput('')
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.delete('search')
      next.delete('q')
      next.delete('priority')
      next.delete('service_id')
      next.delete('status')
      next.set('page', '1')
      return next
    })
  }

  // Accessibility & badge helpers
  const getPriorityBadgeClass = (priority: FindingPriority) => {
    switch (priority.toLowerCase()) {
      case 'highest':
        return 'border-rose-500/40 bg-rose-500/15 text-rose-300'
      case 'high':
        return 'border-orange-500/40 bg-orange-500/15 text-orange-300'
      case 'medium':
        return 'border-amber-500/40 bg-amber-500/15 text-amber-300'
      case 'low':
        return 'border-blue-500/40 bg-blue-500/15 text-blue-300'
      default:
        return 'border-slate-600 bg-slate-800 text-slate-300'
    }
  }

  const getStatusBadgeClass = (status: FindingTriageStatus) => {
    switch (status.toLowerCase()) {
      case 'open':
        return 'border-sky-500/40 bg-sky-500/15 text-sky-300'
      case 'under_investigation':
        return 'border-purple-500/40 bg-purple-500/15 text-purple-300'
      case 'affected':
        return 'border-rose-500/40 bg-rose-500/15 text-rose-300'
      case 'not_affected':
        return 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
      case 'fixed':
        return 'border-teal-500/40 bg-teal-500/15 text-teal-300'
      default:
        return 'border-slate-600 bg-slate-800 text-slate-300'
    }
  }

  const formatStatusLabel = (status: string) => {
    switch (status.toLowerCase()) {
      case 'under_investigation':
        return 'Under Investigation'
      case 'not_affected':
        return 'Not Affected'
      default:
        return status.charAt(0).toUpperCase() + status.slice(1)
    }
  }

  const hasActiveFilters =
    urlSearchTerm.trim() !== '' ||
    priorityFilter !== 'ALL' ||
    serviceFilter !== 'ALL' ||
    statusFilter !== 'ALL'

  // Empty state: No active project
  if (!activeProject) {
    return (
      <div className="rounded-xl border border-dashed border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
        <AlertCircle className="mx-auto h-8 w-8 text-amber-400" aria-hidden="true" />
        <h2 className="mt-3 text-sm font-bold text-white">No Active Project Selected</h2>
        <p className="mt-1 text-slate-400">
          Please select or create a project in the top navigation bar to view findings.
        </p>
      </div>
    )
  }

  const startItem = findingsData.total === 0 ? 0 : (currentPage - 1) * findingsData.page_size + 1
  const endItem = Math.min(currentPage * findingsData.page_size, findingsData.total)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-white">Findings</h1>
            <span className="rounded-full bg-red-500/20 border border-red-500/30 px-2.5 py-0.5 text-xs font-semibold text-red-300">
              {findingsData.total} {findingsData.total === 1 ? 'finding' : 'findings'}
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Advisories matched to package versions with architectural dependency evidence for{' '}
            <span className="font-semibold text-slate-200">{activeProject.name}</span>.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Link
            to="/import"
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-sky-400 transition-colors focus:ring-2 focus:ring-sky-500 focus:outline-none"
          >
            <span>Import / Sync</span>
          </Link>
          <button
            type="button"
            onClick={() => {
              void loadFindings(activeProject.id)
              void loadSummary(activeProject.id)
              void loadWarnings(activeProject.id)
            }}
            disabled={isLoading || isSummaryLoading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-700 hover:text-white transition-colors disabled:opacity-50 focus:ring-2 focus:ring-sky-500 focus:outline-none"
            title="Refresh findings list and summary metrics"
            aria-label="Refresh findings list and summary metrics"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${isLoading || isSummaryLoading ? 'animate-spin text-sky-400' : ''}`}
              aria-hidden="true"
            />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </div>
      </div>

      {/* Data Quality & Scope Warning Banner */}
      <DataQualityBanner warnings={warnings} />

      {/* Findings Error State */}
      {error && (
        <div
          role="alert"
          className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-200"
        >
          <div className="flex items-start gap-2.5">
            <AlertCircle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" aria-hidden="true" />
            <div>
              <p className="font-semibold">{error}</p>
              {errorRequestId && (
                <p className="text-[11px] text-rose-300/80 font-mono mt-0.5">
                  Request ID: {errorRequestId}
                </p>
              )}
            </div>
          </div>
          <button
            type="button"
            onClick={() => void loadFindings(activeProject.id)}
            className="self-start sm:self-auto rounded bg-rose-500/20 px-3 py-1.5 font-semibold text-rose-200 hover:bg-rose-500/30 transition-colors focus:ring-2 focus:ring-rose-400 focus:outline-none"
          >
            Retry
          </button>
        </div>
      )}

      {/* Summary Error State */}
      {summaryError && (
        <div
          role="alert"
          className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3.5 text-xs text-rose-200"
        >
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-rose-400 shrink-0" aria-hidden="true" />
            <span>{summaryError}</span>
          </div>
          <button
            type="button"
            onClick={() => void loadSummary(activeProject.id)}
            className="self-start sm:self-auto rounded bg-rose-500/20 px-2.5 py-1 font-semibold text-rose-200 hover:bg-rose-500/30 transition-colors focus:ring-2 focus:ring-rose-400 focus:outline-none"
          >
            Retry Summary
          </button>
        </div>
      )}

      {/* 4 Data-Driven Summary Cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4" role="region" aria-label="Security Findings Summary">
        {/* Card 1: Advisory Matches */}
        <div
          data-testid="summary-card-advisory-matches"
          className="rounded-xl border border-slate-800 bg-[#0f1822] p-4.5 shadow-sm"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">Advisory Matches</span>
            <ShieldAlert className="h-4 w-4 text-amber-400" aria-hidden="true" />
          </div>
          <div className="mt-3 text-2xl font-bold text-white">
            {isSummaryLoading ? (
              <Loader2 className="h-6 w-6 animate-spin text-slate-500" aria-label="Loading advisory matches" />
            ) : (
              summaryData?.advisory_matches ?? 0
            )}
          </div>
          <p className="mt-1.5 text-[11px] text-slate-400">
            Confirmed advisory matches
          </p>
        </div>

        {/* Card 2: Findings With a Path */}
        <div
          data-testid="summary-card-findings-with-path"
          className="rounded-xl border border-slate-800 bg-[#0f1822] p-4.5 shadow-sm"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">Findings With a Path</span>
            <Route className="h-4 w-4 text-rose-400" aria-hidden="true" />
          </div>
          <div className="mt-3 text-2xl font-bold text-rose-300">
            {isSummaryLoading ? (
              <Loader2 className="h-6 w-6 animate-spin text-slate-500" aria-label="Loading findings with path" />
            ) : (
              summaryData?.findings_with_path ?? 0
            )}
          </div>
          <p className="mt-1.5 text-[11px] text-slate-400">
            Reachable via service call chain
          </p>
        </div>

        {/* Card 3: Findings With No Path */}
        <div
          data-testid="summary-card-findings-without-path"
          className="rounded-xl border border-slate-800 bg-[#0f1822] p-4.5 shadow-sm"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">Findings With No Path</span>
            <ShieldCheck className="h-4 w-4 text-emerald-400" aria-hidden="true" />
          </div>
          <div className="mt-3 text-2xl font-bold text-emerald-300">
            {isSummaryLoading ? (
              <Loader2 className="h-6 w-6 animate-spin text-slate-500" aria-label="Loading findings with no path" />
            ) : (
              summaryData?.findings_without_path ?? 0
            )}
          </div>
          <p className="mt-1.5 text-[11px] text-slate-400">
            No service dependency path found
          </p>
        </div>

        {/* Card 4: Findings Needing a Decision */}
        <div
          data-testid="summary-card-findings-needing-decision"
          className="rounded-xl border border-slate-800 bg-[#0f1822] p-4.5 shadow-sm"
        >
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">Findings Needing a Decision</span>
            <Clock className="h-4 w-4 text-sky-400" aria-hidden="true" />
          </div>
          <div className="mt-3 text-2xl font-bold text-sky-300">
            {isSummaryLoading ? (
              <Loader2 className="h-6 w-6 animate-spin text-slate-500" aria-label="Loading findings needing decision" />
            ) : (
              summaryData?.findings_needing_decision ?? 0
            )}
          </div>
          <p className="mt-1.5 text-[11px] text-slate-400">
            Awaiting triage or review decision
          </p>
        </div>
      </div>

      {/* Search and Filters Bar */}
      <div className="flex flex-col gap-3 rounded-xl border border-slate-800 bg-[#0f1822] p-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Search Advisory or Package */}
          <div className="relative">
            <label htmlFor={searchInputId} className="sr-only">
              Search advisory or package
            </label>
            <Search
              className="absolute left-3 top-2.5 h-4 w-4 text-slate-400 pointer-events-none"
              aria-hidden="true"
            />
            <input
              id={searchInputId}
              type="search"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search advisory or package..."
              className="w-full rounded-lg border border-slate-700 bg-[#0b121a] py-2 pl-9 pr-8 text-xs text-slate-200 placeholder-slate-500 transition-colors focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
            {searchInput && (
              <button
                type="button"
                onClick={() => setSearchInput('')}
                className="absolute right-2.5 top-2.5 text-slate-400 hover:text-white"
                aria-label="Clear search"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            )}
          </div>

          {/* Priority Filter */}
          <div className="flex items-center gap-2">
            <label htmlFor={prioritySelectId} className="sr-only">
              Filter by Priority
            </label>
            <div className="relative w-full">
              <select
                id={prioritySelectId}
                value={priorityFilter}
                onChange={(e) => handlePriorityChange(e.target.value)}
                className="w-full appearance-none rounded-lg border border-slate-700 bg-[#0b121a] px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
              >
                <option value="ALL">All Priorities</option>
                <option value="Highest">Highest</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
                <option value="unknown">Unknown</option>
              </select>
              <Filter
                className="pointer-events-none absolute right-3 top-2.5 h-3.5 w-3.5 text-slate-400"
                aria-hidden="true"
              />
            </div>
          </div>

          {/* Service Filter */}
          <div className="flex items-center gap-2">
            <label htmlFor={serviceSelectId} className="sr-only">
              Filter by Service
            </label>
            <div className="relative w-full">
              <select
                id={serviceSelectId}
                value={serviceFilter}
                onChange={(e) => handleServiceChange(e.target.value)}
                className="w-full appearance-none rounded-lg border border-slate-700 bg-[#0b121a] px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
              >
                <option value="ALL">All Services</option>
                {services.map((svc) => (
                  <option key={svc.id} value={svc.id}>
                    {svc.name}
                  </option>
                ))}
              </select>
              <Filter
                className="pointer-events-none absolute right-3 top-2.5 h-3.5 w-3.5 text-slate-400"
                aria-hidden="true"
              />
            </div>
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-2">
            <label htmlFor={statusSelectId} className="sr-only">
              Filter by Status
            </label>
            <div className="relative w-full">
              <select
                id={statusSelectId}
                value={statusFilter}
                onChange={(e) => handleStatusChange(e.target.value)}
                className="w-full appearance-none rounded-lg border border-slate-700 bg-[#0b121a] px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="open">Open</option>
                <option value="under_investigation">Under Investigation</option>
                <option value="affected">Affected</option>
                <option value="not_affected">Not Affected</option>
                <option value="fixed">Fixed</option>
              </select>
              <Filter
                className="pointer-events-none absolute right-3 top-2.5 h-3.5 w-3.5 text-slate-400"
                aria-hidden="true"
              />
            </div>
          </div>
        </div>

        {/* Filter Summary & Clear Action */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-2 border-t border-slate-800/60 text-xs text-slate-400">
          <div>
            Showing <span className="font-semibold text-white">{startItem}-{endItem}</span> of{' '}
            <span className="font-semibold text-white">{findingsData.total}</span> findings
          </div>
          {hasActiveFilters && (
            <button
              type="button"
              onClick={handleClearFilters}
              className="inline-flex items-center gap-1 text-sky-400 hover:text-sky-300 font-medium focus:ring-2 focus:ring-sky-500 focus:outline-none rounded px-1"
            >
              <X className="h-3 w-3" aria-hidden="true" />
              <span>Clear active filters</span>
            </button>
          )}
        </div>
      </div>

      {/* Findings Table Card */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] shadow-xl overflow-hidden">
        {isLoading ? (
          <div
            role="status"
            aria-live="polite"
            className="flex flex-col items-center justify-center p-16 text-slate-400"
          >
            <Loader2 className="h-8 w-8 animate-spin text-sky-400" aria-hidden="true" />
            <span className="mt-3 text-xs font-medium text-slate-300">
              Loading vulnerability findings...
            </span>
          </div>
        ) : findingsData.total === 0 ? (
          hasActiveFilters ? (
            /* Empty State B: No matches for active search/filters */
            <div className="p-12 text-center text-xs text-slate-400">
              <Filter className="mx-auto h-8 w-8 text-slate-500" aria-hidden="true" />
              <h2 className="mt-3 font-semibold text-white">No Matching Findings</h2>
              <p className="mt-1 text-slate-500">
                No findings match the selected filters or search criteria.
              </p>
              <button
                type="button"
                onClick={handleClearFilters}
                className="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition-colors focus:ring-2 focus:ring-sky-500 focus:outline-none"
              >
                <span>Reset Filters</span>
              </button>
            </div>
          ) : (
            /* Empty State A: Project has no findings at all */
            <div className="p-12 text-center text-xs text-slate-400">
              <ShieldCheck className="mx-auto h-8 w-8 text-emerald-400" aria-hidden="true" />
              <h2 className="mt-3 font-semibold text-white">No Confirmed Vulnerabilities</h2>
              <p className="mt-1 text-slate-400 max-w-md mx-auto">
                No active vulnerability matches exist for this project. Either dependencies have not
                been imported, no advisories matched, or installed versions are outside affected ranges.
              </p>
              <p className="mt-2 text-[11px] text-slate-500">
                Note: Absence of findings reflects analyzed dependencies and does not guarantee complete absence of risk.
              </p>
              <Link
                to="/import"
                className="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-2 text-xs font-semibold text-white hover:bg-sky-400 transition-colors focus:ring-2 focus:ring-sky-500 focus:outline-none"
              >
                <span>Import Dependencies / Advisories</span>
              </Link>
            </div>
          )
        ) : (
          /* Populated State */
          <div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs" aria-label="Vulnerability Findings Table">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900/50 text-slate-400">
                    <th scope="col" className="py-3 px-4 font-semibold">
                      Priority
                    </th>
                    <th scope="col" className="py-3 px-4 font-semibold">
                      Advisory
                    </th>
                    <th scope="col" className="py-3 px-4 font-semibold">
                      Package &amp; Version
                    </th>
                    <th scope="col" className="py-3 px-4 font-semibold">
                      Service
                    </th>
                    <th scope="col" className="py-3 px-4 font-semibold">
                      Path Depth
                    </th>
                    <th scope="col" className="py-3 px-4 font-semibold">
                      Status
                    </th>
                    <th scope="col" className="py-3 px-4 font-semibold text-right">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {findingsData.items.map((finding) => (
                    <tr
                      key={finding.id}
                      className="hover:bg-slate-900/40 transition-colors"
                    >
                      {/* 1. Priority */}
                      <td className="py-3 px-4 align-top">
                        <div className="flex flex-col items-start gap-1">
                          <span
                            className={`inline-block rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border ${getPriorityBadgeClass(
                              finding.priority,
                            )}`}
                            title={
                              finding.priority_reasons && finding.priority_reasons.length > 0
                                ? `Vulnify Priority: ${finding.priority}\n\nReasons:\n• ${finding.priority_reasons.join('\n• ')}`
                                : `Vulnify Priority: ${finding.priority}`
                            }
                          >
                            {finding.priority}
                          </span>
                          {finding.priority_reasons && finding.priority_reasons.length > 0 && (
                            <span
                              className="text-[10px] text-slate-400 line-clamp-1 max-w-[140px] cursor-help"
                              title={finding.priority_reasons.join('; ')}
                            >
                              {finding.priority_reasons[0]}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* 2. Advisory */}
                      <td className="py-3 px-4 align-top max-w-xs">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono font-semibold text-white">
                            {finding.advisory_id}
                          </span>
                          {finding.source_url && (
                            <a
                              href={finding.source_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-slate-400 hover:text-sky-400 transition-colors"
                              title="Open advisory source"
                              aria-label={`Open external advisory source for ${finding.advisory_id}`}
                            >
                              <ExternalLink className="h-3 w-3" aria-hidden="true" />
                            </a>
                          )}
                        </div>
                        {finding.advisory_summary ? (
                          <p
                            className="mt-0.5 line-clamp-2 text-slate-300 text-[11px]"
                            title={finding.advisory_summary}
                          >
                            {finding.advisory_summary}
                          </p>
                        ) : (
                          <p className="mt-0.5 text-slate-500 italic text-[11px]">
                            No advisory summary provided
                          </p>
                        )}
                      </td>

                      {/* 3. Package & Version */}
                      <td className="py-3 px-4 align-top">
                        <div className="font-semibold text-white">{finding.package_name}</div>
                        <div className="flex items-center gap-1.5 mt-0.5">
                          <span className="font-mono text-slate-400 text-[11px]">
                            @{finding.package_version}
                          </span>
                          <span className="rounded bg-slate-800 border border-slate-700 px-1.5 py-0.2 text-[9px] font-mono text-slate-300">
                            {finding.ecosystem}
                          </span>
                        </div>
                      </td>

                      {/* 4. Service */}
                      <td className="py-3 px-4 align-top">
                        <div className="inline-flex items-center gap-1 font-mono text-slate-200">
                          <Layers className="h-3 w-3 text-slate-400 shrink-0" aria-hidden="true" />
                          <span>{finding.service_name || 'Unassigned'}</span>
                        </div>
                      </td>

                      {/* 5. Path Depth */}
                      <td className="py-3 px-4 align-top">
                        {finding.path_status === 'path_found' && finding.path_depth !== null ? (
                          <div className="flex items-center gap-1">
                            <span
                              className={`rounded px-1.5 py-0.5 font-mono text-[11px] font-semibold border ${
                                finding.path_depth === 1
                                  ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                                  : 'border-sky-500/40 bg-sky-500/10 text-sky-300'
                              }`}
                            >
                              Depth: {finding.path_depth}
                            </span>
                            <span className="text-[10px] text-slate-400">
                              {finding.path_depth === 1 ? '(Direct)' : '(Transitive)'}
                            </span>
                          </div>
                        ) : finding.path_status === 'no_path_found' ? (
                          <div
                            className="inline-flex flex-col gap-0.5 text-slate-400"
                            title="No reachable path found from service within search depth. Does not guarantee safety."
                          >
                            <div className="inline-flex items-center gap-1">
                              <span className="italic">No path found</span>
                              <HelpCircle className="h-3 w-3 text-slate-500" aria-hidden="true" />
                            </div>
                            <span className="text-[10px] text-amber-300 font-medium">
                              Safety not guaranteed
                            </span>
                          </div>
                        ) : (
                          <span className="text-slate-500 italic">Unavailable</span>
                        )}
                      </td>

                      {/* 6. Status */}
                      <td className="py-3 px-4 align-top">
                        <div className="flex flex-col items-start gap-1">
                          <span
                            className={`inline-block rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider border ${getStatusBadgeClass(
                              finding.status,
                            )}`}
                          >
                            {formatStatusLabel(finding.status)}
                          </span>
                          {finding.review_required && (
                            <span
                              className="inline-flex items-center gap-1 rounded bg-rose-500/20 border border-rose-500/30 px-1.5 py-0.5 text-[9px] font-bold text-rose-300"
                              title={finding.review_reason || 'Evidence supporting prior decision has changed.'}
                            >
                              Needs Review
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-4 align-top text-right">
                        <Link
                          to={`/findings/${encodeURIComponent(finding.id)}`}
                          className="inline-flex items-center gap-1 rounded bg-slate-800 px-2.5 py-1 text-slate-200 hover:bg-slate-700 hover:text-white font-semibold transition-colors focus:ring-2 focus:ring-sky-500 focus:outline-none"
                          aria-label={`Inspect evidence for finding ${finding.advisory_id} on ${finding.package_name}`}
                        >
                          <span>Evidence</span>
                          <ArrowRight className="h-3 w-3" aria-hidden="true" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-slate-800 bg-slate-900/30 p-4 text-xs text-slate-400">
              <div>
                Page <span className="font-semibold text-white">{findingsData.page}</span> of{' '}
                <span className="font-semibold text-white">{findingsData.total_pages || 1}</span>{' '}
                ({findingsData.total} total items)
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => handlePageChange(currentPage - 1)}
                  disabled={currentPage <= 1 || isLoading}
                  className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 font-medium text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed focus:ring-2 focus:ring-sky-500 focus:outline-none"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Previous</span>
                </button>

                <span className="px-2 py-1 font-mono text-xs text-slate-300">
                  {currentPage} / {findingsData.total_pages || 1}
                </span>

                <button
                  type="button"
                  onClick={() => handlePageChange(currentPage + 1)}
                  disabled={currentPage >= (findingsData.total_pages || 1) || isLoading}
                  className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 font-medium text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed focus:ring-2 focus:ring-sky-500 focus:outline-none"
                  aria-label="Next page"
                >
                  <span>Next</span>
                  <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
