import { useState, useEffect, useMemo, useRef } from 'react'
import { Link, useSearchParams } from 'react-router'
import {
  Bot,
  Send,
  Terminal,
  StopCircle,
  Sparkles,
  Database,
  CheckCircle2,
  Clock,
  AlertTriangle,
  ExternalLink,
  RotateCcw,
  X,
} from 'lucide-react'
import { useProjects } from '@/features/projects/ProjectProvider'
import { getProjectVulnerabilities } from '@/features/projects/projectApi'
import type { VulnerabilityFinding } from '@/features/projects/types'
import {
  cancelAgentRun,
  streamAgentInvestigation,
  getAgentRunTrace,
  type AgentStreamEvent,
  type ToolStepInfo,
} from './agentApi'
import { TraceDrawer } from './TraceDrawer'

interface ChatMessage {
  id: string
  sender: 'user' | 'agent'
  text: string
  timestamp: string
  runId?: string
  toolCalls?: ToolStepInfo[]
  findingsReferenced?: string[]
  pathsReferenced?: string[]
  statusText?: string
  isStreaming?: boolean
  isCancelled?: boolean
  isError?: boolean
  errorMessage?: string
}

export function AiInvestigationPage() {
  const { activeProject } = useProjects()
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([])

  const [inputQuery, setInputQuery] = useState('')
  const [isThinking, setIsThinking] = useState(false)
  const [isTraceOpen, setIsTraceOpen] = useState(true)
  const [activeRunId, setActiveRunId] = useState<string | null>(null)
  const [currentStatusText, setCurrentStatusText] = useState<string | null>(null)
  const [activeToolSteps, setActiveToolSteps] = useState<ToolStepInfo[]>([])

  // US-603: URL Reopen & Trace Drawer State
  const [searchParams, setSearchParams] = useSearchParams()
  const reopenRunId = searchParams.get('reopen')
  const [traceDrawerRunId, setTraceDrawerRunId] = useState<string | null>(null)
  const [isTraceDrawerOpen, setIsTraceDrawerOpen] = useState(false)
  const [reopenedRunMeta, setReopenedRunMeta] = useState<{
    id: string
    startedAt: number
    status: string
  } | null>(null)

  const abortControllerRef = useRef<AbortController | null>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      sender: 'agent',
      text: "Hello! I am Vulnify's graph-augmented security investigation agent. I query your FalkorDB knowledge graph directly using parameterized tools to inspect dependency reachability, exposure paths, priority rankings, and candidate fixes. All answers are grounded strictly in graph facts and OSV advisory records. How can I help investigate your project?",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ])

  useEffect(() => {
    if (activeProject) {
      getProjectVulnerabilities(activeProject.id)
        .then((data) => setFindings(data))
        .catch(() => setFindings([]))
    }
  }, [activeProject])

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isThinking, currentStatusText, activeToolSteps])

  // US-603: Load historical run when ?reopen={runId} is provided
  useEffect(() => {
    if (!reopenRunId) {
      setReopenedRunMeta(null)
      return
    }

    let isMounted = true
    setIsThinking(false)
    setCurrentStatusText('Loading historical investigation trace from FalkorDB...')

    async function loadReopenedRun() {
      try {
        const trace = await getAgentRunTrace(reopenRunId!)
        if (!isMounted) return

        const { run, tool_calls } = trace
        const startTimeStr = new Date(run.started_at * 1000).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
        })
        const endTimeStr = run.completed_at
          ? new Date(run.completed_at * 1000).toLocaleTimeString([], {
              hour: '2-digit',
              minute: '2-digit',
            })
          : startTimeStr

        const mappedSteps: ToolStepInfo[] = (tool_calls || []).map((tc) => ({
          callId: tc.id,
          toolName: tc.tool_name,
          displayName: tc.tool_name,
          inputs: tc.inputs || {},
          status:
            tc.status === 'success'
              ? 'completed'
              : tc.status === 'running'
              ? 'running'
              : 'error',
          resultSummary: tc.result_summary,
          durationMs: tc.duration_ms ?? undefined,
          queryId: tc.query_id ?? undefined,
          evidenceReferences: tc.evidence_references,
        }))

        const userMsg: ChatMessage = {
          id: `reopened-user-${run.id}`,
          sender: 'user',
          text: run.prompt,
          timestamp: startTimeStr,
        }

        const agentMsg: ChatMessage = {
          id: `reopened-agent-${run.id}`,
          sender: 'agent',
          text:
            run.final_answer ||
            (run.status === 'cancelled'
              ? 'Run was cancelled by user.'
              : run.status === 'timeout'
              ? 'Run timed out after maximum duration.'
              : 'Historical investigation run completed without text output.'),
          timestamp: endTimeStr,
          runId: run.id,
          toolCalls: mappedSteps,
          findingsReferenced: run.findings_referenced,
          pathsReferenced: run.paths_referenced,
          isCancelled: run.status === 'cancelled',
          isError: run.status === 'error' || run.status === 'failed',
          errorMessage: run.error_message ?? undefined,
          isStreaming: false,
          statusText: `Reopened Run • Status: ${run.status}`,
        }

        setMessages([userMsg, agentMsg])
        setActiveRunId(run.id)
        setActiveToolSteps(mappedSteps)
        setReopenedRunMeta({
          id: run.id,
          startedAt: run.started_at,
          status: run.status,
        })
        setCurrentStatusText(null)
      } catch (err: any) {
        if (!isMounted) return
        setCurrentStatusText(null)
        console.error('Failed to load historical run trace:', err)
      }
    }

    void loadReopenedRun()

    return () => {
      isMounted = false
    }
  }, [reopenRunId])

  const handleClearReopenedRun = () => {
    setSearchParams({})
    setReopenedRunMeta(null)
    setActiveRunId(null)
    setActiveToolSteps([])
    setMessages([
      {
        id: 'welcome',
        sender: 'agent',
        text: "Hello! I am Vulnify's graph-augmented security investigation agent. I query your FalkorDB knowledge graph directly using parameterized tools to inspect dependency reachability, exposure paths, priority rankings, and candidate fixes. All answers are grounded strictly in graph facts and OSV advisory records. How can I help investigate your project?",
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ])
  }

  // Context-aware prompt suggestions based on actual project findings
  const suggestedPrompts = useMemo(() => {
    if (!activeProject || findings.length === 0) {
      return [
        'How does Vulnify model exposure paths in FalkorDB?',
        'What is the difference between architectural exposure and exploitability?',
        'Which findings currently have known candidate fixes?',
      ]
    }

    const topFinding = findings[0]!
    const criticalFindings = findings.filter((f) => f.severity.toUpperCase() === 'CRITICAL')
    const withFix = findings.filter((f) => f.fixed_version)

    return [
      `Explain the exposure path for ${topFinding.package_name}@${topFinding.package_version}`,
      criticalFindings.length > 0
        ? `Which of the ${criticalFindings.length} critical findings have direct reachability?`
        : `Which findings in ${activeProject.name} have dependency paths?`,
      withFix.length > 0
        ? `What candidate fixes exist for ${withFix[0]!.package_name}?`
        : 'Which findings currently lack an upstream fix?',
      `Rank all vulnerability findings for ${activeProject.name} with priority reasons`,
    ]
  }, [activeProject, findings])

  const handleStopRun = async () => {
    if (!activeRunId) return

    try {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort()
      }
      await cancelAgentRun(activeRunId)
    } catch (err) {
      console.warn('Failed to send cancellation signal:', err)
    } finally {
      setIsThinking(false)
      setCurrentStatusText('Run cancelled by user.')
      setMessages((prev) =>
        prev.map((m) =>
          m.runId === activeRunId
            ? {
                ...m,
                isStreaming: false,
                isCancelled: true,
                statusText: 'Run cancelled by user.',
              }
            : m,
        ),
      )
    }
  }

  const handleSendMessage = async (textToSend?: string) => {
    const query = (textToSend ?? inputQuery).trim()
    if (!query || isThinking || !activeProject) return

    const userMsgId = `user-${Date.now()}`
    const agentMsgId = `agent-${Date.now()}`
    const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

    const userMsg: ChatMessage = {
      id: userMsgId,
      sender: 'user',
      text: query,
      timestamp: timeStr,
    }

    const initialAgentMsg: ChatMessage = {
      id: agentMsgId,
      sender: 'agent',
      text: '',
      timestamp: timeStr,
      toolCalls: [],
      isStreaming: true,
      statusText: 'Connecting to agent orchestrator...',
    }

    setMessages((prev) => [...prev, userMsg, initialAgentMsg])
    if (!textToSend) setInputQuery('')
    setIsThinking(true)
    setCurrentStatusText('Connecting to agent orchestrator...')
    setActiveToolSteps([])

    const abortController = new AbortController()
    abortControllerRef.current = abortController

    try {
      await streamAgentInvestigation({
        projectId: activeProject.id,
        message: query,
        signal: abortController.signal,
        onEvent: (event: AgentStreamEvent) => {
          handleIncomingEvent(event, agentMsgId)
        },
        onError: (err: Error) => {
          setIsThinking(false)
          setCurrentStatusText(null)
          setMessages((prev) =>
            prev.map((m) =>
              m.id === agentMsgId
                ? {
                    ...m,
                    isStreaming: false,
                    isError: true,
                    errorMessage: err.message || 'Stream connection failed',
                  }
                : m,
            ),
          )
        },
      })
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        setIsThinking(false)
        setCurrentStatusText(null)
        setMessages((prev) =>
          prev.map((m) =>
            m.id === agentMsgId
              ? {
                  ...m,
                  isStreaming: false,
                  isError: true,
                  errorMessage: err.message || 'Investigation request failed',
                }
              : m,
          ),
        )
      }
    }
  }

  const handleIncomingEvent = (event: AgentStreamEvent, agentMsgId: string) => {
    const { event: eventName, run_id, data } = event

    if (eventName === 'run_started') {
      setActiveRunId(run_id)
      setMessages((prev) =>
        prev.map((m) => (m.id === agentMsgId ? { ...m, runId: run_id } : m)),
      )
    } else if (eventName === 'assistant_status') {
      const statusText = data.status_text || 'Thinking...'
      setCurrentStatusText(statusText)
      setMessages((prev) =>
        prev.map((m) => (m.id === agentMsgId ? { ...m, statusText } : m)),
      )
    } else if (eventName === 'tool_started') {
      const newStep: ToolStepInfo = {
        callId: data.call_id,
        toolName: data.tool_name,
        displayName: data.display_name || data.tool_name,
        inputs: data.inputs || {},
        status: 'running',
      }
      setActiveToolSteps((prev) => [...prev, newStep])
      setMessages((prev) =>
        prev.map((m) =>
          m.id === agentMsgId
            ? { ...m, toolCalls: [...(m.toolCalls || []), newStep] }
            : m,
        ),
      )
    } else if (eventName === 'tool_completed') {
      setActiveToolSteps((prev) =>
        prev.map((t) =>
          t.callId === data.call_id
            ? {
                ...t,
                status: data.status === 'success' ? 'completed' : 'error',
                resultSummary: data.result_summary,
                durationMs: data.duration_ms,
                outcome: data.outcome,
                evidenceReferences: data.evidence_references,
                queryId: data.trace?.query_id,
              }
            : t,
        ),
      )
      setMessages((prev) =>
        prev.map((m) =>
          m.id === agentMsgId
            ? {
                ...m,
                toolCalls: (m.toolCalls || []).map((t) =>
                  t.callId === data.call_id
                    ? {
                        ...t,
                        status: data.status === 'success' ? 'completed' : 'error',
                        resultSummary: data.result_summary,
                        durationMs: data.duration_ms,
                        outcome: data.outcome,
                        evidenceReferences: data.evidence_references,
                        queryId: data.trace?.query_id,
                      }
                    : t,
                ),
              }
            : m,
        ),
      )
    } else if (eventName === 'answer_delta') {
      const delta = data.delta || ''
      setMessages((prev) =>
        prev.map((m) =>
          m.id === agentMsgId ? { ...m, text: m.text + delta } : m,
        ),
      )
    } else if (eventName === 'answer_completed') {
      setMessages((prev) =>
        prev.map((m) =>
          m.id === agentMsgId
            ? {
                ...m,
                text: data.full_text || m.text,
                findingsReferenced: data.findings_referenced,
                pathsReferenced: data.paths_referenced,
              }
            : m,
        ),
      )
    } else if (eventName === 'run_completed') {
      setIsThinking(false)
      setCurrentStatusText(null)
      setMessages((prev) =>
        prev.map((m) =>
          m.id === agentMsgId
            ? { ...m, isStreaming: false, statusText: undefined }
            : m,
        ),
      )
    } else if (eventName === 'run_cancelled') {
      setIsThinking(false)
      setCurrentStatusText('Run cancelled.')
      setMessages((prev) =>
        prev.map((m) =>
          m.id === agentMsgId
            ? {
                ...m,
                isStreaming: false,
                isCancelled: true,
                statusText: data.reason || 'Run cancelled by user.',
              }
            : m,
        ),
      )
    } else if (eventName === 'run_timeout') {
      setIsThinking(false)
      setCurrentStatusText('Run timed out.')
      setMessages((prev) =>
        prev.map((m) =>
          m.id === agentMsgId
            ? {
                ...m,
                isStreaming: false,
                isError: true,
                errorMessage: data.message || 'Run timed out after maximum duration.',
              }
            : m,
        ),
      )
    } else if (eventName === 'run_step_limit') {
      setIsThinking(false)
      setCurrentStatusText('Step limit reached.')
      setMessages((prev) =>
        prev.map((m) =>
          m.id === agentMsgId
            ? {
                ...m,
                isStreaming: false,
                isError: true,
                errorMessage: data.message || 'Step limit budget reached.',
              }
            : m,
        ),
      )
    } else if (eventName === 'run_failed') {
      setIsThinking(false)
      setCurrentStatusText(null)
      setMessages((prev) =>
        prev.map((m) =>
          m.id === agentMsgId
            ? {
                ...m,
                isStreaming: false,
                isError: true,
                errorMessage: data.error_message || 'Agent investigation failed.',
              }
            : m,
        ),
      )
    }
  }

  // Helper to parse markdown links safely into native React Router Links or safe spans
  const renderFormattedText = (rawText: string) => {
    // Matches markdown links like [find-123](/findings/find-123)
    const linkRegex = /\[(.*?)\]\((.*?)\)/g
    const elements: React.ReactNode[] = []
    let lastIndex = 0
    let match: RegExpExecArray | null

    while ((match = linkRegex.exec(rawText)) !== null) {
      if (match.index > lastIndex) {
        elements.push(rawText.substring(lastIndex, match.index))
      }
      const label = match[1]!
      const href = match[2]!

      if (href.startsWith('/findings/')) {
        elements.push(
          <Link
            key={`link-${match.index}`}
            to={href}
            className="text-sky-400 hover:text-sky-300 font-semibold underline inline-flex items-center gap-0.5"
          >
            <span>{label}</span>
            <ExternalLink className="h-3 w-3 inline" />
          </Link>,
        )
      } else {
        elements.push(
          <span key={`span-${match.index}`} className="font-semibold text-slate-200">
            {label}
          </span>,
        )
      }
      lastIndex = match.index + match[0].length
    }

    if (lastIndex < rawText.length) {
      elements.push(rawText.substring(lastIndex))
    }

    return elements
  }

  const latestToolCall = useMemo(() => {
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i]?.toolCalls && messages[i]!.toolCalls!.length > 0) {
        const calls = messages[i]!.toolCalls!
        return calls[calls.length - 1]!
      }
    }
    return null
  }, [messages])

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white">AI Security Investigation</h1>
            <span className="rounded-full bg-sky-500/15 border border-sky-500/30 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-sky-300">
              US-602 &bull; Streaming Agent
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Interactive reasoning agent grounded directly in FalkorDB graph queries and OSV vulnerability records.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Link
            to="/investigation-history"
            className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-700 hover:bg-slate-800 transition"
          >
            <Clock className="h-3.5 w-3.5 text-amber-400" />
            <span>Investigation History</span>
          </Link>

          <button
            type="button"
            onClick={() => setIsTraceOpen(!isTraceOpen)}
            className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-700 hover:bg-slate-800"
          >
            <Database className="h-3.5 w-3.5 text-sky-400" />
            <span>{isTraceOpen ? 'Hide Graph Trace' : 'Show Graph Trace'}</span>
          </button>
        </div>
      </div>

      {/* Safety & Honesty Banner (US-604 & US-605) */}
      <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-3.5 text-xs text-sky-200">
        <div className="flex items-start gap-2.5">
          <Terminal className="h-4 w-4 text-sky-400 mt-0.5 shrink-0" aria-hidden="true" />
          <div className="space-y-0.5">
            <span className="font-semibold text-white">Agent Grounding & Non-Exploitability Policy:</span>
            <p className="text-sky-200/90 leading-relaxed">
              Vulnify’s agent queries live FalkorDB knowledge graph tools and never invents findings or paths.
              Paths reflect architectural exposure, never claiming exploitability. Advisory descriptions are
              treated as untrusted data.
            </p>
          </div>
        </div>
      </div>

      {/* Reopened Historical Run Banner (US-603) */}
      {reopenedRunMeta && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3.5 text-xs text-amber-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-start sm:items-center gap-2.5">
            <RotateCcw className="h-4 w-4 text-amber-400 mt-0.5 sm:mt-0 shrink-0" />
            <div>
              <span className="font-semibold text-white">Reopened Historical Run: </span>
              <span className="font-mono text-amber-300">{reopenedRunMeta.id}</span>
              <span className="ml-2 px-1.5 py-0.5 rounded bg-amber-500/20 text-[10px] font-mono uppercase text-amber-200 border border-amber-500/30">
                {reopenedRunMeta.status}
              </span>
              <span className="ml-2 text-amber-300/80 text-[11px]">
                (Read-only audit transcript. Stored FalkorDB graph state preserved.)
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto">
            <button
              type="button"
              onClick={() => {
                setTraceDrawerRunId(reopenedRunMeta.id)
                setIsTraceDrawerOpen(true)
              }}
              className="px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-[11px] font-medium text-amber-200 border border-amber-500/30 transition"
            >
              View Full Trace
            </button>
            <button
              type="button"
              onClick={handleClearReopenedRun}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[11px] font-medium text-slate-200 border border-slate-700 transition"
            >
              <X className="h-3.5 w-3.5" />
              <span>Start New Run</span>
            </button>
          </div>
        </div>
      )}

      {/* Suggested Prompt Pills */}
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          <Sparkles className="h-3.5 w-3.5 text-amber-400" />
          <span>Suggested Inquiries for {activeProject ? activeProject.name : 'Active Project'}</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {suggestedPrompts.map((promptText, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleSendMessage(promptText)}
              disabled={isThinking}
              className="rounded-lg border border-slate-800 bg-[#0f1822] px-3 py-1.5 text-xs text-slate-300 hover:border-sky-500/50 hover:bg-slate-800/80 hover:text-white transition disabled:opacity-50 text-left"
            >
              {promptText}
            </button>
          ))}
        </div>
      </div>

      {/* Main Workspace Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Chat Conversation Stream */}
        <div
          className={`${
            isTraceOpen ? 'lg:col-span-8' : 'lg:col-span-12'
          } flex flex-col h-[620px] rounded-xl border border-slate-800 bg-[#0f1822] shadow-xl overflow-hidden`}
        >
          {/* Chat Messages Region */}
          <div className="flex-1 overflow-y-auto p-5 space-y-4 scrollbar-thin scrollbar-thumb-slate-800">
            {messages.map((m) => (
              <div
                key={m.id}
                className={`flex gap-3 text-xs leading-relaxed ${
                  m.sender === 'user' ? 'justify-end' : 'justify-start'
                }`}
              >
                {m.sender === 'agent' && (
                  <div className="h-7 w-7 rounded-lg bg-sky-500/20 border border-sky-500/40 flex items-center justify-center shrink-0">
                    <Bot className="h-4 w-4 text-sky-400" />
                  </div>
                )}

                <div
                  className={`max-w-[85%] rounded-xl p-4 shadow-sm ${
                    m.sender === 'user'
                      ? 'bg-sky-500 text-white rounded-tr-none'
                      : 'bg-[#0b121a] border border-slate-800 text-slate-200 rounded-tl-none space-y-3'
                  }`}
                >
                  {/* Tool Activity Steps (Emitted Live via SSE) */}
                  {m.toolCalls && m.toolCalls.length > 0 && (
                    <div className="space-y-1.5 pb-2 border-b border-slate-800/80">
                      <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1">
                        <Terminal className="h-3 w-3 text-sky-400" />
                        <span>Live Tool Execution Steps ({m.toolCalls.length})</span>
                      </div>
                      <div className="space-y-1">
                        {m.toolCalls.map((tc) => (
                          <div
                            key={tc.callId}
                            className="flex items-center justify-between rounded bg-[#0f1822] border border-slate-800/90 px-2.5 py-1 text-[11px] font-mono text-slate-300"
                          >
                            <div className="flex items-center gap-2 truncate">
                              {tc.status === 'running' ? (
                                <Clock className="h-3 w-3 text-amber-400 animate-spin shrink-0" />
                              ) : tc.status === 'completed' ? (
                                <CheckCircle2 className="h-3 w-3 text-emerald-400 shrink-0" />
                              ) : (
                                <AlertTriangle className="h-3 w-3 text-red-400 shrink-0" />
                              )}
                              <span className="font-semibold text-sky-300">{tc.toolName}</span>
                              {tc.queryId && (
                                <span className="text-[10px] text-slate-500 truncate">
                                  ({tc.queryId})
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-2 shrink-0 text-[10px] text-slate-400">
                              {tc.durationMs !== undefined && <span>{tc.durationMs}ms</span>}
                              <span
                                className={`px-1.5 py-0.2 rounded text-[9px] uppercase ${
                                  tc.status === 'completed'
                                    ? 'bg-emerald-500/15 text-emerald-300'
                                    : tc.status === 'running'
                                      ? 'bg-amber-500/15 text-amber-300'
                                      : 'bg-red-500/15 text-red-300'
                                }`}
                              >
                                {tc.status}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Main Message Text with Formatted Finding Links */}
                  <div className="whitespace-pre-wrap leading-relaxed">
                    {renderFormattedText(m.text)}
                    {m.isStreaming && (
                      <span className="inline-block w-1.5 h-3 ml-1 bg-sky-400 animate-pulse" />
                    )}
                  </div>

                  {/* Error Callout */}
                  {m.isError && m.errorMessage && (
                    <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-2.5 text-xs text-red-200 flex items-start gap-2">
                      <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
                      <div>
                        <div className="font-semibold">Investigation Error</div>
                        <div>{m.errorMessage}</div>
                      </div>
                    </div>
                  )}

                  {/* Cancellation Note */}
                  {m.isCancelled && (
                    <div className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-[11px] text-amber-200 flex items-center gap-1.5">
                      <StopCircle className="h-3.5 w-3.5 text-amber-400" />
                      <span>{m.statusText || 'Run was cancelled by user.'}</span>
                    </div>
                  )}

                  {/* Timestamp, Status, and Trace Drawer Action (US-603) */}
                  <div className="text-[10px] text-slate-500 flex items-center justify-between mt-2 pt-2 border-t border-slate-800/60">
                    <div className="flex items-center gap-2">
                      {m.runId && (
                        <>
                          <span className="font-mono text-slate-400">Run: {m.runId.substring(0, 14)}...</span>
                          <button
                            type="button"
                            onClick={() => {
                              setTraceDrawerRunId(m.runId!)
                              setIsTraceDrawerOpen(true)
                            }}
                            className="inline-flex items-center gap-1 text-sky-400 hover:text-sky-300 font-medium transition-colors"
                            title="Open persistent execution audit trace"
                          >
                            <Database className="h-3 w-3" />
                            <span>View Audit Trace</span>
                          </button>
                        </>
                      )}
                      {m.isStreaming && currentStatusText && (
                        <span className="text-sky-400 animate-pulse">{currentStatusText}</span>
                      )}
                    </div>
                    <span>{m.timestamp}</span>
                  </div>
                </div>
              </div>
            ))}

            {isThinking && (
              <div className="flex gap-3 text-xs justify-start items-center">
                <div className="h-7 w-7 rounded-lg bg-sky-500/20 border border-sky-500/40 flex items-center justify-center shrink-0 animate-pulse">
                  <Bot className="h-4 w-4 text-sky-400" />
                </div>
                <div className="rounded-xl bg-[#0b121a] border border-slate-800 p-3 text-slate-300 flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-sky-400 animate-ping" />
                  <span>{currentStatusText || 'Executing graph tools and synthesizing evidence...'}</span>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input & Action Bar */}
          <div className="border-t border-slate-800 bg-[#0b121a] p-3">
            <form
              onSubmit={(e) => {
                e.preventDefault()
                handleSendMessage()
              }}
              className="flex items-center gap-2"
            >
              <input
                type="text"
                value={inputQuery}
                onChange={(e) => setInputQuery(e.target.value)}
                placeholder="Ask about exposure paths, priority reasons, or candidate upgrades..."
                disabled={isThinking || !activeProject}
                className="flex-1 rounded-lg border border-slate-800 bg-[#0f1822] px-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 disabled:opacity-50"
              />

              {isThinking ? (
                <button
                  type="button"
                  onClick={handleStopRun}
                  className="flex items-center gap-1.5 rounded-lg border border-red-500/40 bg-red-500/15 px-3 py-2 text-xs font-semibold text-red-300 hover:bg-red-500/25 transition"
                >
                  <StopCircle className="h-4 w-4" />
                  Stop Run
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={!inputQuery.trim() || !activeProject}
                  className="flex items-center gap-1.5 rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-400 disabled:opacity-40 disabled:cursor-not-allowed transition"
                >
                  <Send className="h-3.5 w-3.5" />
                  Ask Agent
                </button>
              )}
            </form>
          </div>
        </div>

        {/* Right Column: FalkorDB Query Transparency Drawer */}
        {isTraceOpen && (
          <div className="lg:col-span-4 h-[620px] flex flex-col rounded-xl border border-slate-800 bg-[#0f1822] shadow-xl overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-800/80 px-4 py-3">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-sky-400" />
                <h3 className="text-xs font-semibold text-white uppercase tracking-wider">
                  FalkorDB Tool Trace
                </h3>
              </div>
              <div className="flex items-center gap-2">
                {activeRunId && (
                  <button
                    type="button"
                    onClick={() => {
                      setTraceDrawerRunId(activeRunId)
                      setIsTraceDrawerOpen(true)
                    }}
                    className="rounded bg-sky-500/15 hover:bg-sky-500/25 text-[10px] font-mono text-sky-300 px-2 py-0.5 border border-sky-500/30 transition"
                  >
                    Open Drawer
                  </button>
                )}
                <span className="rounded bg-slate-800 text-[10px] font-mono text-slate-300 px-2 py-0.5 border border-slate-700">
                  FastMCP
                </span>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs font-mono">
              {latestToolCall ? (
                <div className="space-y-3">
                  <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 space-y-1.5">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">
                      Executed Tool
                    </div>
                    <div className="text-sky-300 font-semibold">{latestToolCall.toolName}</div>
                    <div className="text-slate-400 text-[11px]">
                      Query ID: {latestToolCall.queryId || 'graph_query'}
                    </div>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 space-y-1.5">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">
                      Parameterized Inputs
                    </div>
                    <pre className="text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(latestToolCall.inputs, null, 2)}
                    </pre>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 space-y-1.5">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">
                      Tool Result Summary
                    </div>
                    <div className="text-[11px] text-slate-300 font-sans leading-relaxed">
                      {latestToolCall.resultSummary || 'Operation completed successfully.'}
                    </div>
                    {latestToolCall.durationMs !== undefined && (
                      <div className="text-[10px] text-slate-500 pt-1">
                        Execution time: {latestToolCall.durationMs}ms
                      </div>
                    )}
                  </div>

                  {latestToolCall.evidenceReferences &&
                    latestToolCall.evidenceReferences.length > 0 && (
                      <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 space-y-1.5">
                        <div className="text-[10px] text-slate-500 uppercase tracking-wider">
                          Referenced Evidence
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {latestToolCall.evidenceReferences.map((refId) => (
                            <span
                              key={refId}
                              className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] text-sky-300"
                            >
                              {refId}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                </div>
              ) : (
                <div className="text-center py-20 text-slate-500 font-sans text-xs space-y-2">
                  <Terminal className="h-6 w-6 mx-auto text-slate-600" />
                  <p>No tool execution trace active yet.</p>
                  <p className="text-[11px] text-slate-600">
                    Submit an inquiry to inspect live FalkorDB queries, parameterized inputs, and execution latency.
                  </p>
                </div>
              )}
            </div>

            <div className="border-t border-slate-800/80 p-3 bg-[#0b121a] text-[10px] text-slate-500 font-sans flex items-center justify-between">
              <span>FastMCP Registry &bull; Bounded Traversals</span>
              <span className="text-emerald-400 font-medium">10-Step Budget</span>
            </div>
          </div>
        )}
      </div>

      {/* Embedded Slide-over Trace Drawer (US-603) */}
      <TraceDrawer
        runId={traceDrawerRunId}
        isOpen={isTraceDrawerOpen}
        onClose={() => setIsTraceDrawerOpen(false)}
        onReopenRun={(run) => {
          setSearchParams({ reopen: run.id })
          setIsTraceDrawerOpen(false)
        }}
      />
    </div>
  )
}
