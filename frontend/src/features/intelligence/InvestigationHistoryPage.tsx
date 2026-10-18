import { useEffect, useState, useMemo } from 'react'
import { Link, useNavigate } from 'react-router'
import {
  Database,
  Search,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  StopCircle,
  ExternalLink,
  Loader2,
  RefreshCw,
  Clock,
  ShieldAlert,
  Bot,
} from 'lucide-react'
import { useProjects } from '@/features/projects/ProjectProvider'
import {
  listAgentRuns,
  type AgentRunSummary,
  type AgentRunDetail,
} from './agentApi'
import { TraceDrawer } from './TraceDrawer'

export function InvestigationHistoryPage() {
  const { activeProject } = useProjects()
  const navigate = useNavigate()

  const [runs, setRuns] = useState<AgentRunSummary[]>([])
  const [totalCount, setTotalCount] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize] = useState(15)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')

  // Trace Drawer State
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null)
  const [isDrawerOpen, setIsDrawerOpen] = useState(false)

  const fetchRuns = async () => {
    if (!activeProject) return
    setIsLoading(true)
    setError(null)

    try {
      const response = await listAgentRuns(activeProject.id, page, pageSize)
      setRuns(response.items)
      setTotalCount(response.total)
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve investigation run history.')
      setRuns([])
      setTotalCount(0)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    void fetchRuns()
  }, [activeProject, page, pageSize])

  // Client-side filtering across the page results
  const filteredRuns = useMemo(() => {
    return runs.filter((r) => {
      const matchesSearch =
        !searchQuery.trim() ||
        r.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        r.prompt.toLowerCase().includes(searchQuery.toLowerCase()) ||
        r.user_email.toLowerCase().includes(searchQuery.toLowerCase())

      const matchesStatus =
        statusFilter === 'all' || r.status.toLowerCase() === statusFilter.toLowerCase()

      return matchesSearch && matchesStatus
    })
  }, [runs, searchQuery, statusFilter])

  const handleOpenTrace = (runId: string) => {
    setSelectedRunId(runId)
    setIsDrawerOpen(true)
  }

  const handleReopenInChat = (run: AgentRunDetail | AgentRunSummary) => {
    navigate(`/investigation?reopen=${encodeURIComponent(run.id)}`)
  }

  const formatTimestamp = (ts?: number | null) => {
    if (!ts) return 'N/A'
    try {
      const d = new Date(ts * 1000)
      return d.toLocaleString([], {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
      })
    } catch {
      return 'N/A'
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 border border-emerald-500/30 px-2 py-0.5 text-[11px] font-medium text-emerald-300">
            <CheckCircle2 className="h-3 w-3" />
            <span>Completed</span>
          </span>
        )
      case 'running':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-amber-500/15 border border-amber-500/30 px-2 py-0.5 text-[11px] font-medium text-amber-300">
            <Clock className="h-3 w-3 animate-spin" />
            <span>Running</span>
          </span>
        )
      case 'cancelled':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-slate-500/15 border border-slate-500/30 px-2 py-0.5 text-[11px] font-medium text-slate-300">
            <StopCircle className="h-3 w-3" />
            <span>Cancelled</span>
          </span>
        )
      case 'timeout':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-orange-500/15 border border-orange-500/30 px-2 py-0.5 text-[11px] font-medium text-orange-300">
            <Clock className="h-3 w-3" />
            <span>Timed Out</span>
          </span>
        )
      case 'step_limit':
        return (
          <span className="inline-flex items-center gap-1 rounded bg-purple-500/15 border border-purple-500/30 px-2 py-0.5 text-[11px] font-medium text-purple-300">
            <AlertTriangle className="h-3 w-3" />
            <span>Step Limit</span>
          </span>
        )
      case 'error':
      case 'failed':
      default:
        return (
          <span className="inline-flex items-center gap-1 rounded bg-red-500/15 border border-red-500/30 px-2 py-0.5 text-[11px] font-medium text-red-300">
            <AlertTriangle className="h-3 w-3" />
            <span>Failed</span>
          </span>
        )
    }
  }

  const totalPages = Math.max(1, Math.ceil(totalCount / pageSize))

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white">Investigation History & Stored Traces</h1>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Persistent audit record of agent reasoning sessions, Cypher tool calls, and grounded decision transcripts.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={fetchRuns}
            disabled={isLoading}
            className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-[#0f1822] px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-700 hover:bg-slate-800 transition disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <Link
            to="/investigation"
            className="flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-sky-400 transition"
          >
            <Bot className="h-3.5 w-3.5" />
            <span>New Investigation</span>
          </Link>
        </div>
      </div>

      {/* Honesty & Provenance Banner */}
      <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-3.5 text-xs text-sky-200">
        <div className="flex items-start gap-2.5">
          <Database className="h-4 w-4 text-sky-400 mt-0.5 shrink-0" aria-hidden="true" />
          <div className="space-y-0.5">
            <span className="font-semibold text-white">Immutable Graph Audit Trail:</span>
            <p className="text-sky-200/90 leading-relaxed">
              Every agent execution session is recorded in FalkorDB with exact parameterized tool invocations,
              timing, and query IDs. Sensitive fields (tokens, secrets, credentials) are scrubbed before persistence.
              Reopening a run provides a verifiable read-only audit transcript.
            </p>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 rounded-xl border border-slate-800 bg-[#0f1822] p-3 shadow-lg">
        <div className="relative w-full sm:w-80">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by Run ID, prompt, or user..."
            className="w-full rounded-lg border border-slate-800 bg-[#0b121a] pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
          />
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto justify-end">
          <div className="flex items-center gap-2">
            <label htmlFor="status-filter" className="text-xs text-slate-400 font-medium">Status:</label>
            <select
              id="status-filter"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-lg border border-slate-800 bg-[#0b121a] px-3 py-1.5 text-xs text-slate-200 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            >
              <option value="all">All Statuses</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="cancelled">Cancelled</option>
              <option value="timeout">Timed Out</option>
              <option value="step_limit">Step Limit</option>
              <option value="error">Failed</option>
            </select>
          </div>
        </div>
      </div>

      {/* Error Callout */}
      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-xs text-red-200 flex items-start gap-2.5">
          <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold">Unable to Load Investigation History</div>
            <p className="mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {/* Main Table / State Container */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] shadow-xl overflow-hidden">
        {isLoading && runs.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-20 text-slate-400 space-y-3">
            <Loader2 className="h-8 w-8 animate-spin text-sky-400" />
            <p className="text-xs font-medium text-slate-300">Loading stored investigation runs...</p>
          </div>
        ) : filteredRuns.length === 0 ? (
          <div className="p-16 text-center text-xs text-slate-400 space-y-3">
            <ShieldAlert className="mx-auto h-8 w-8 text-slate-500" />
            <div className="font-semibold text-slate-300 text-sm">
              {searchQuery || statusFilter !== 'all'
                ? 'No investigation runs match your criteria'
                : 'No past investigation runs found'}
            </div>
            <p className="text-slate-500 max-w-md mx-auto">
              {searchQuery || statusFilter !== 'all'
                ? 'Try adjusting your search terms or filter settings.'
                : `No agent investigation runs have been executed for ${activeProject?.name || 'this project'} yet. Ask the Agent in AI Investigation to analyze exposure and candidate fixes.`}
            </p>
            {!searchQuery && statusFilter === 'all' && (
              <div className="pt-2">
                <Link
                  to="/investigation"
                  className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3.5 py-2 text-xs font-semibold text-white shadow-sm hover:bg-sky-400 transition"
                >
                  <Bot className="h-3.5 w-3.5" />
                  <span>Start First Investigation</span>
                </Link>
              </div>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-slate-800 bg-[#0b121a] text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                <tr>
                  <th scope="col" className="px-4 py-3">Run ID</th>
                  <th scope="col" className="px-4 py-3">Timestamp</th>
                  <th scope="col" className="px-4 py-3">User Prompt</th>
                  <th scope="col" className="px-4 py-3">Status</th>
                  <th scope="col" className="px-4 py-3 text-center">Steps</th>
                  <th scope="col" className="px-4 py-3">Duration</th>
                  <th scope="col" className="px-4 py-3 text-right">Audit Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {filteredRuns.map((r) => {
                  const durationSec =
                    r.completed_at && r.started_at
                      ? Math.max(0, r.completed_at - r.started_at).toFixed(1)
                      : null

                  return (
                    <tr key={r.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-4 py-3 font-mono font-medium text-sky-400 whitespace-nowrap">
                        <button
                          type="button"
                          onClick={() => handleOpenTrace(r.id)}
                          className="hover:underline flex items-center gap-1"
                          title="Click to view execution trace"
                        >
                          <span>{r.id.substring(0, 12)}...</span>
                          <ExternalLink className="h-3 w-3 text-slate-500" />
                        </button>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-slate-400 font-mono text-[11px]">
                        {formatTimestamp(r.started_at)}
                      </td>
                      <td className="px-4 py-3 max-w-xs truncate" title={r.prompt}>
                        <span className="font-medium text-slate-200">{r.prompt}</span>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        {getStatusBadge(r.status)}
                      </td>
                      <td className="px-4 py-3 text-center whitespace-nowrap font-mono">
                        <span className="inline-block px-2 py-0.5 rounded bg-slate-800 text-[11px] text-slate-300 font-medium">
                          {r.tool_call_count} step{r.tool_call_count === 1 ? '' : 's'}
                        </span>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap font-mono text-slate-400 text-[11px]">
                        {durationSec ? `${durationSec}s` : '—'}
                      </td>
                      <td className="px-4 py-3 text-right whitespace-nowrap space-x-2">
                        <button
                          type="button"
                          onClick={() => handleOpenTrace(r.id)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[11px] font-medium text-slate-200 border border-slate-700 transition"
                        >
                          <Database className="h-3 w-3 text-sky-400" />
                          <span>View Trace</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => handleReopenInChat(r)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-sky-500/15 hover:bg-sky-500/25 text-[11px] font-medium text-sky-300 border border-sky-500/30 transition"
                          title="Reopen historical run in AI chat"
                        >
                          <RotateCcw className="h-3 w-3 text-sky-400" />
                          <span>Reopen in Chat</span>
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {totalCount > pageSize && (
          <div className="flex items-center justify-between border-t border-slate-800 bg-[#0b121a] px-4 py-3 text-xs text-slate-400">
            <div>
              Showing <span className="font-medium text-white">{runs.length}</span> of{' '}
              <span className="font-medium text-white">{totalCount}</span> investigation runs
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1 || isLoading}
                className="rounded border border-slate-800 px-2.5 py-1 text-slate-300 hover:bg-slate-800 disabled:opacity-40 transition"
              >
                Previous
              </button>
              <span className="px-2 font-mono text-[11px]">
                Page {page} of {totalPages}
              </span>
              <button
                type="button"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages || isLoading}
                className="rounded border border-slate-800 px-2.5 py-1 text-slate-300 hover:bg-slate-800 disabled:opacity-40 transition"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Embedded Slide-over Trace Drawer */}
      <TraceDrawer
        runId={selectedRunId}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        onReopenRun={handleReopenInChat}
      />
    </div>
  )
}
