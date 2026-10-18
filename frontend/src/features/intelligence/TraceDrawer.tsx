import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import {
  X,
  Database,
  Clock,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Loader2,
  Terminal,
  Lock,
  RotateCcw,
} from 'lucide-react'
import {
  getAgentRunTrace,
  type AgentRunTraceResponse,
  type AgentToolCallDetail,
  type AgentRunDetail,
} from './agentApi'

interface TraceDrawerProps {
  runId: string | null
  isOpen: boolean
  onClose: () => void
  onReopenRun?: (run: AgentRunDetail) => void
}

export function TraceDrawer({ runId, isOpen, onClose, onReopenRun }: TraceDrawerProps) {
  const [traceData, setTraceData] = useState<AgentRunTraceResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expandedCalls, setExpandedCalls] = useState<Set<string>>(new Set())

  // Fetch trace whenever runId changes and drawer is open
  useEffect(() => {
    if (!isOpen || !runId) {
      setTraceData(null)
      setError(null)
      return
    }

    let isMounted = true
    setIsLoading(true)
    setError(null)

    async function loadTrace() {
      try {
        const data = await getAgentRunTrace(runId!)
        if (isMounted) {
          setTraceData(data)
          // Default expand all completed tool calls if <= 3 calls, else expand only the first
          const defaultExpanded = new Set<string>()
          if (data.tool_calls.length <= 3) {
            data.tool_calls.forEach((c) => defaultExpanded.add(c.id))
          } else if (data.tool_calls.length > 0) {
            defaultExpanded.add(data.tool_calls[0]!.id)
          }
          setExpandedCalls(defaultExpanded)
        }
      } catch (err: any) {
        if (isMounted) {
          setError(err.message || 'Failed to retrieve agent trace records.')
        }
      } finally {
        if (isMounted) {
          setIsLoading(false)
        }
      }
    }

    void loadTrace()

    return () => {
      isMounted = false
    }
  }, [isOpen, runId])

  // Close on Escape key press
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape' && isOpen) {
        onClose()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  if (!isOpen) return null

  const toggleCallExpanded = (callId: string) => {
    setExpandedCalls((prev) => {
      const next = new Set(prev)
      if (next.has(callId)) {
        next.delete(callId)
      } else {
        next.add(callId)
      }
      return next
    })
  }

  const formatTimestamp = (ts?: number | null) => {
    if (!ts) return 'N/A'
    try {
      const d = new Date(ts * 1000)
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    } catch {
      return 'N/A'
    }
  }

  const run = traceData?.run
  const toolCalls = traceData?.tool_calls || []

  // Check if inputs contain redacted values
  const hasRedactedValue = (obj: any): boolean => {
    if (!obj) return false
    const str = JSON.stringify(obj)
    return str.includes('[REDACTED]')
  }

  return (
    <div
      className="fixed inset-0 z-50 overflow-hidden"
      role="dialog"
      aria-modal="true"
      aria-labelledby="trace-drawer-title"
    >
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Slide-over panel */}
      <div className="fixed inset-y-0 right-0 max-w-full flex pl-10">
        <div className="w-screen max-w-2xl bg-[#0f1822] border-l border-slate-800 shadow-2xl flex flex-col">
          {/* Drawer Header */}
          <div className="p-4 border-b border-slate-800 bg-[#0b121a] flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-sky-500/10 border border-sky-500/20 text-sky-400">
                <Database className="h-4 w-4" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 id="trace-drawer-title" className="text-sm font-bold text-white tracking-tight">
                    Investigation Execution Trace
                  </h2>
                </div>
                <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                  Run ID: {runId || 'Unknown'}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {run && onReopenRun && (
                <button
                  type="button"
                  onClick={() => {
                    onReopenRun(run)
                    onClose()
                  }}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700 transition-colors"
                >
                  <RotateCcw className="h-3.5 w-3.5 text-sky-400" />
                  <span>Reopen in Chat</span>
                </button>
              )}
              <button
                type="button"
                onClick={onClose}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors focus:outline-none focus:ring-2 focus:ring-sky-500"
                aria-label="Close trace drawer"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
          </div>

          {/* Drawer Body */}
          <div className="flex-1 overflow-y-auto p-5 space-y-5">
            {/* Loading State */}
            {isLoading && (
              <div className="flex flex-col items-center justify-center py-24 text-slate-400 space-y-3">
                <Loader2 className="h-8 w-8 animate-spin text-sky-400" />
                <p className="text-xs font-medium text-slate-300">Retrieving audit trace from FalkorDB...</p>
                <p className="text-[11px] text-slate-500">Loading ordered tool invocations and query identifiers.</p>
              </div>
            )}

            {/* Error State */}
            {error && !isLoading && (
              <div className="rounded-xl border border-rose-900/40 bg-rose-950/20 p-5 text-center space-y-3">
                <AlertTriangle className="h-8 w-8 text-rose-400 mx-auto" />
                <h3 className="text-sm font-semibold text-white">Trace Retrieval Failed</h3>
                <p className="text-xs text-rose-300 max-w-sm mx-auto">{error}</p>
                <button
                  type="button"
                  onClick={() => {
                    setError(null)
                    setIsLoading(true)
                  }}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white border border-slate-700"
                >
                  Retry Retrieval
                </button>
              </div>
            )}

            {/* Populated Content */}
            {!isLoading && !error && run && (
              <>
                {/* Run Overview Metadata Card */}
                <div className="rounded-xl border border-slate-800 bg-[#0b121a] p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] text-slate-400">Status:</span>
                      <span
                        className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${
                          run.status === 'completed'
                            ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                            : run.status === 'cancelled'
                            ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                            : run.status === 'running'
                            ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                            : 'bg-rose-500/15 border-rose-500/30 text-rose-300'
                        }`}
                      >
                        {run.status}
                      </span>
                    </div>

                    <div className="flex items-center gap-3 text-[11px] text-slate-400">
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3 text-slate-500" />
                        Started: {formatTimestamp(run.started_at)}
                      </span>
                      {run.completed_at && (
                        <span>
                          Duration:{' '}
                          <strong className="text-slate-300">
                            {Math.max(0, run.completed_at - run.started_at)}s
                          </strong>
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Investigation Prompt */}
                  <div className="space-y-1">
                    <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">
                      User Prompt
                    </span>
                    <p className="text-xs text-slate-200 bg-[#0f1822] p-2.5 rounded-lg border border-slate-800/80 font-sans leading-relaxed">
                      {run.prompt || 'Prompt not recorded.'}
                    </p>
                  </div>

                  {/* User Email & Project */}
                  <div className="flex flex-wrap items-center gap-4 text-[11px] text-slate-400 pt-1">
                    <span>
                      Actor: <strong className="text-slate-300">{run.user_email}</strong>
                    </span>
                    <span>
                      Project ID: <strong className="font-mono text-slate-300">{run.project_id}</strong>
                    </span>
                    <span>
                      Steps: <strong className="text-slate-300">{run.step_count}</strong>
                    </span>
                  </div>

                  {/* Failure Warning */}
                  {run.error_message && (
                    <div className="rounded-lg border border-rose-800/40 bg-rose-950/20 p-2.5 text-xs text-rose-300 flex items-start gap-2">
                      <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400 mt-0.5" />
                      <div>
                        <strong>Investigation Interrupted:</strong> {run.error_message}
                      </div>
                    </div>
                  )}
                </div>

                {/* Tool Calls Section Header */}
                <div className="flex items-center justify-between pt-1">
                  <div className="flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-sky-400" />
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                      Ordered Tool Executions ({toolCalls.length})
                    </h3>
                  </div>
                  <span className="text-[10px] text-slate-500">
                    Chronological audit sequence
                  </span>
                </div>

                {/* Empty Tool Calls State */}
                {toolCalls.length === 0 && (
                  <div className="rounded-xl border border-dashed border-slate-800 bg-[#0b121a]/50 p-8 text-center text-slate-500 space-y-2">
                    <Database className="h-6 w-6 mx-auto text-slate-600" />
                    <p className="text-xs font-medium text-slate-400">No tool calls recorded for this run.</p>
                    <p className="text-[11px] text-slate-600">
                      The agent session did not execute any registered graph tools before terminating.
                    </p>
                  </div>
                )}

                {/* Tool Calls Timeline */}
                {toolCalls.length > 0 && (
                  <div className="space-y-3">
                    {toolCalls.map((call: AgentToolCallDetail) => {
                      const isExpanded = expandedCalls.has(call.id)
                      const isRedacted = hasRedactedValue(call.inputs)

                      return (
                        <div
                          key={call.id}
                          className="rounded-xl border border-slate-800 bg-[#0b121a] overflow-hidden transition-all shadow-sm"
                        >
                          {/* Card Header (Clickable Accordion) */}
                          <button
                            type="button"
                            onClick={() => toggleCallExpanded(call.id)}
                            className="w-full text-left p-3.5 flex items-center justify-between hover:bg-slate-800/30 transition-colors gap-3"
                          >
                            <div className="flex items-center gap-2.5 min-w-0">
                              <span className="shrink-0 flex items-center justify-center h-5 w-5 rounded-full bg-sky-500/10 text-sky-400 text-[10px] font-mono font-bold border border-sky-500/20">
                                #{call.sequence}
                              </span>

                              <div className="truncate">
                                <div className="flex items-center gap-2 truncate">
                                  <span className="text-xs font-semibold text-white font-mono">
                                    {call.tool_name}
                                  </span>
                                  {call.query_id && (
                                    <span className="rounded bg-sky-500/10 border border-sky-500/20 px-1.5 py-0.2 text-[10px] font-mono text-sky-300 truncate">
                                      {call.query_id}
                                    </span>
                                  )}
                                  {isRedacted && (
                                    <span className="inline-flex items-center gap-0.5 rounded bg-amber-500/15 border border-amber-500/30 px-1.5 py-0.2 text-[9px] font-semibold text-amber-300">
                                      <Lock className="h-2.5 w-2.5" />
                                      Redacted
                                    </span>
                                  )}
                                </div>
                                {call.display_name && (
                                  <div className="text-[11px] text-slate-400 truncate">
                                    {call.display_name}
                                  </div>
                                )}
                              </div>
                            </div>

                            <div className="flex items-center gap-2.5 shrink-0">
                              {call.duration_ms !== null && call.duration_ms !== undefined && (
                                <span className="text-[10px] font-mono text-slate-400">
                                  {call.duration_ms.toFixed(1)}ms
                                </span>
                              )}

                              <span
                                className={`text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${
                                  call.status === 'success'
                                    ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                                    : call.status === 'rejected'
                                    ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                                    : 'bg-rose-500/15 border-rose-500/30 text-rose-300'
                                }`}
                              >
                                {call.status}
                              </span>

                              {isExpanded ? (
                                <ChevronUp className="h-4 w-4 text-slate-400" />
                              ) : (
                                <ChevronDown className="h-4 w-4 text-slate-400" />
                              )}
                            </div>
                          </button>

                          {/* Accordion Expandable Content */}
                          {isExpanded && (
                            <div className="p-3.5 border-t border-slate-800/80 bg-[#080d14] space-y-3 text-xs font-sans">
                              {/* Result Summary */}
                              <div className="space-y-1">
                                <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">
                                  Execution Summary
                                </span>
                                <div className="text-slate-200 bg-[#0f1822] p-2.5 rounded-lg border border-slate-800 text-xs leading-relaxed">
                                  {call.result_summary || 'Operation recorded without descriptive summary.'}
                                </div>
                              </div>

                              {/* Parameterized Inputs */}
                              <div className="space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">
                                    Parameterized Inputs
                                  </span>
                                  {isRedacted && (
                                    <span className="text-[10px] text-amber-400">
                                      *Sensitive credentials sanitized before storage
                                    </span>
                                  )}
                                </div>
                                <pre className="text-[11px] font-mono text-sky-200 bg-[#0f1822] p-2.5 rounded-lg border border-slate-800 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                                  {JSON.stringify(call.inputs, null, 2)}
                                </pre>
                              </div>

                              {/* Evidence References */}
                              {call.evidence_references && call.evidence_references.length > 0 && (
                                <div className="space-y-1.5">
                                  <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">
                                    Entity & Finding References ({call.evidence_references.length})
                                  </span>
                                  <div className="flex flex-wrap gap-1.5">
                                    {call.evidence_references.map((refId) => {
                                      const isFinding = refId.startsWith('find-')
                                      if (isFinding) {
                                        return (
                                          <Link
                                            key={refId}
                                            to={`/findings/${encodeURIComponent(refId)}`}
                                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-sky-500/10 hover:bg-sky-500/20 border border-sky-500/30 text-[11px] font-mono text-sky-300 transition-colors"
                                          >
                                            <span>{refId}</span>
                                            <ExternalLink className="h-2.5 w-2.5" />
                                          </Link>
                                        )
                                      }
                                      return (
                                        <span
                                          key={refId}
                                          className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-[11px] font-mono text-slate-300"
                                        >
                                          {refId}
                                        </span>
                                      )
                                    })}
                                  </div>
                                </div>
                              )}

                              {/* Execution Metadata Footer */}
                              <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] text-slate-500 pt-1 border-t border-slate-800/60 font-mono">
                                <span>Tool ID: {call.id}</span>
                                <span>
                                  Outcome: <strong className="text-slate-400">{call.outcome || 'standard'}</strong>
                                </span>
                              </div>
                            </div>
                          )}
                        </div>
                      )
                    })}
                  </div>
                )}

                {/* Final Answer Preview Section */}
                {run.final_answer && (
                  <div className="rounded-xl border border-slate-800 bg-[#0b121a] p-4 space-y-2">
                    <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">
                      Persisted Final Conclusion
                    </span>
                    <div className="text-xs text-slate-300 bg-[#0f1822] p-3 rounded-lg border border-slate-800/80 leading-relaxed font-sans whitespace-pre-wrap">
                      {run.final_answer}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Drawer Footer */}
          <div className="p-3.5 border-t border-slate-800 bg-[#0b121a] flex items-center justify-between text-xs text-slate-500">
            <span>FalkorDB Provenance Audit &bull; Immutable Trace</span>
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
