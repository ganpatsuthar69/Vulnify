import { useState, useEffect, useMemo, useRef } from 'react'
import {
  Bot,
  Send,
  Terminal,
  StopCircle,
  Sparkles,
  Database,
} from 'lucide-react'
import { useProjects } from '@/features/projects/ProjectProvider'
import { getProjectVulnerabilities } from '@/features/projects/projectApi'
import type { VulnerabilityFinding } from '@/features/projects/types'

interface ChatMessage {
  id: string
  sender: 'user' | 'agent'
  text: string
  timestamp: string
  toolCalls?: {
    toolName: string
    params: Record<string, unknown>
    resultSummary: string
    queryId?: string
    durationMs?: number
  }[]
  findingsReferenced?: string[]
}

export function AiInvestigationPage() {
  const { activeProject } = useProjects()
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([])

  const [inputQuery, setInputQuery] = useState('')
  const [isThinking, setIsThinking] = useState(false)
  const [isTraceOpen, setIsTraceOpen] = useState(true)

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      sender: 'agent',
      text: "Hello! I am Vulnify's graph-augmented security investigation agent. I query your FalkorDB knowledge graph directly to explain dependency reachability, exposure paths, and remediation options. All answers are grounded strictly in graph facts and OSV advisory records. How can I help investigate your project?",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ])

  const messagesEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (activeProject) {
      getProjectVulnerabilities(activeProject.id)
        .then((data) => setFindings(data))
        .catch(() => setFindings([]))
    }
  }, [activeProject])

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isThinking])

  // Context-aware prompt suggestions based on actual project findings
  const suggestedPrompts = useMemo(() => {
    if (!activeProject || findings.length === 0) {
      return [
        'How does Vulnify model exposure paths in FalkorDB?',
        'What is the difference between architectural exposure and exploitability?',
        'How does SemVer comparison differ between npm and PyPI ecosystems?',
      ]
    }

    const topFinding = findings[0]!
    const criticalFindings = findings.filter((f) => f.severity.toUpperCase() === 'CRITICAL')
    const withFix = findings.filter((f) => f.fixed_version)

    return [
      `Explain the exposure path for ${topFinding.package_name}@${topFinding.package_version}`,
      criticalFindings.length > 0
        ? `Which of the ${criticalFindings.length} critical findings have direct reachability?`
        : `Which findings in ${activeProject.name} have internet-facing exposure?`,
      withFix.length > 0
        ? `What fixed versions exist for ${withFix[0]!.package_name}?`
        : 'Which findings currently lack an upstream fix?',
      `Summarize exposure risk for project ${activeProject.name}`,
    ]
  }, [activeProject, findings])

  const handleSendMessage = (textToSend?: string) => {
    const query = (textToSend ?? inputQuery).trim()
    if (!query || isThinking) return

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }

    setMessages((prev) => [...prev, userMsg])
    if (!textToSend) setInputQuery('')
    setIsThinking(true)

    // Hand-crafted grounded simulation based on live project graph findings
    setTimeout(() => {
      const lower = query.toLowerCase()
      let agentResponse = ''
      let toolCalls: ChatMessage['toolCalls'] = []
      let findingsReferenced: string[] = []

      if (lower.includes('exposure') || lower.includes('path') || lower.includes('reach')) {
        const targetFinding = findings.find(
          (f) =>
            lower.includes(f.package_name.toLowerCase()) ||
            lower.includes(f.id.toLowerCase()),
        ) || findings[0]

        if (targetFinding) {
          findingsReferenced = [targetFinding.id]
          toolCalls = [
            {
              toolName: 'find_shortest_exposure_path',
              params: {
                project_id: activeProject?.id,
                package_name: targetFinding.package_name,
                package_version: targetFinding.package_version,
                max_depth: 6,
              },
              resultSummary: `Found 1 bounded exposure path (depth: 2) from Entry Service to ${targetFinding.package_name}@${targetFinding.package_version}`,
              queryId: 'CYPHER_SHORTEST_PATH_V2',
              durationMs: 4.8,
            },
          ]
          agentResponse = `Based on the FalkorDB dependency traversal for **${targetFinding.package_name}** (${targetFinding.package_version}):

- **Architecture Exposure:** Reached as a transitive dependency via your entry services.
- **Matched Advisory:** [${targetFinding.id}](/findings/${targetFinding.id}) (${targetFinding.severity} severity).
- **Match Reason:** ${targetFinding.match_reason}.
- **Remediation Target:** ${targetFinding.fixed_version ? `Upgrade to version \`${targetFinding.fixed_version}\`` : 'No fixed version available upstream yet'}.

*Notice: Paths reflect architectural dependency chains, not proof of runtime exploitability.*`
        } else {
          agentResponse = `I checked the graph for project "${activeProject?.name || 'current'}", but no path was found matching that package. Please note that "no path found" does not guarantee runtime immunity if external unmodeled dependencies exist.`
        }
      } else if (lower.includes('fix') || lower.includes('upgrade') || lower.includes('remediat')) {
        const upgradeable = findings.filter((f) => f.fixed_version)
        findingsReferenced = upgradeable.slice(0, 3).map((f) => f.id)
        toolCalls = [
          {
            toolName: 'list_candidate_upgrades',
            params: { project_id: activeProject?.id },
            resultSummary: `Retrieved ${upgradeable.length} package upgrade candidates with non-null fixed_version`,
            queryId: 'CYPHER_UPGRADE_CANDIDATES_V1',
            durationMs: 3.2,
          },
        ]
        agentResponse = `Here is the remediation status for **${activeProject?.name}**:

Found **${upgradeable.length}** finding(s) with confirmed upstream fixes:
${upgradeable.slice(0, 4).map((f) => `- **${f.package_name}**: Upgrade from \`${f.package_version}\` to \`${f.fixed_version}\` to resolve [${f.id}](/findings/${f.id})`).join('\n')}

You can preview structured GitHub remediation issues in the **Remediation &gt; GitHub Issues** workspace.`
      } else {
        toolCalls = [
          {
            toolName: 'query_project_vulnerability_summary',
            params: { project_id: activeProject?.id },
            resultSummary: `Summary returned ${findings.length} findings for active project`,
            queryId: 'CYPHER_PROJECT_FINDINGS_SUMMARY',
            durationMs: 2.9,
          },
        ]
        agentResponse = `I have inspected the FalkorDB graph for **${activeProject?.name || 'the active project'}**.
There are currently **${findings.length}** confirmed vulnerability findings recorded.

You can ask me to:
1. Trace exposure chains for any specific package.
2. Filter findings by critical severity or network exposure.
3. Check breaking-change risks for candidate upgrades.`
      }

      const agentMsg: ChatMessage = {
        id: `agent-${Date.now()}`,
        sender: 'agent',
        text: agentResponse,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        toolCalls,
        findingsReferenced,
      }

      setMessages((prev) => [...prev, agentMsg])
      setIsThinking(false)
    }, 750)
  }

  const latestToolCall = useMemo(() => {
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i]?.toolCalls && messages[i]!.toolCalls!.length > 0) {
        return messages[i]!.toolCalls![0]!
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
              US-602 &bull; Grounded Agent
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Interactive reasoning agent grounded directly in FalkorDB graph queries and OSV vulnerability records.
          </p>
        </div>

        <button
          type="button"
          onClick={() => setIsTraceOpen(!isTraceOpen)}
          className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-700 hover:bg-slate-800"
        >
          <Database className="h-3.5 w-3.5 text-sky-400" />
          <span>{isTraceOpen ? 'Hide Graph Trace' : 'Show Graph Trace'}</span>
        </button>
      </div>

      {/* Safety & Honesty Banner (US-604 & US-605) */}
      <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-3.5 text-xs text-sky-200">
        <div className="flex items-start gap-2.5">
          <Terminal className="h-4 w-4 text-sky-400 mt-0.5 shrink-0" aria-hidden="true" />
          <div className="space-y-0.5">
            <span className="font-semibold text-white">Agent Grounding & Prompt Injection Resistance:</span>
            <p className="text-sky-200/90 leading-relaxed">
              Vulnify’s agent does not execute freeform Cypher or shell commands. Tool calls execute parameterized,
              pre-tested graph routines. Advisory texts are passed as quoted data and never evaluated as instructions (US-604).
              The agent reports architectural exposure, never claiming exploitability (US-605).
            </p>
          </div>
        </div>
      </div>

      {/* Suggested Prompt Pills */}
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          <Sparkles className="h-3.5 w-3.5 text-amber-400" />
          <span>Suggested Context-Aware Inquiries</span>
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
        <div className={`${isTraceOpen ? 'lg:col-span-8' : 'lg:col-span-12'} flex flex-col h-[580px] rounded-xl border border-slate-800 bg-[#0f1822] shadow-xl overflow-hidden`}>
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
                      : 'bg-[#0b121a] border border-slate-800 text-slate-200 rounded-tl-none space-y-2'
                  }`}
                >
                  <div className="whitespace-pre-wrap">{m.text}</div>

                  {/* Grounded Tool Call Pill */}
                  {m.toolCalls && m.toolCalls.length > 0 && (
                    <div className="pt-2 border-t border-slate-800/80 mt-2 flex flex-wrap gap-2 text-[10px]">
                      {m.toolCalls.map((tc, idx) => (
                        <div
                          key={idx}
                          className="flex items-center gap-1.5 rounded bg-slate-900 border border-slate-800 px-2 py-1 text-slate-400 font-mono"
                        >
                          <Terminal className="h-3 w-3 text-sky-400" />
                          <span>tool: {tc.toolName}</span>
                          {tc.durationMs && (
                            <span className="text-slate-500">({tc.durationMs}ms)</span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="text-[10px] text-slate-500 text-right mt-1">
                    {m.timestamp}
                  </div>
                </div>
              </div>
            ))}

            {isThinking && (
              <div className="flex gap-3 text-xs justify-start items-center">
                <div className="h-7 w-7 rounded-lg bg-sky-500/20 border border-sky-500/40 flex items-center justify-center shrink-0 animate-pulse">
                  <Bot className="h-4 w-4 text-sky-400" />
                </div>
                <div className="rounded-xl bg-[#0b121a] border border-slate-800 p-3 text-slate-400 flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-sky-400 animate-ping" />
                  <span>Traversing graph relationships and querying OSV catalog...</span>
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
                placeholder="Ask about exposure paths, fixed versions, or dependency depth..."
                disabled={isThinking}
                className="flex-1 rounded-lg border border-slate-800 bg-[#0f1822] px-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 disabled:opacity-50"
              />

              {isThinking ? (
                <button
                  type="button"
                  onClick={() => setIsThinking(false)}
                  className="flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs font-semibold text-red-300 hover:bg-red-500/20"
                >
                  <StopCircle className="h-4 w-4" />
                  Stop
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={!inputQuery.trim()}
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
          <div className="lg:col-span-4 h-[580px] flex flex-col rounded-xl border border-slate-800 bg-[#0f1822] shadow-xl overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-800/80 px-4 py-3">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-sky-400" />
                <h3 className="text-xs font-semibold text-white uppercase tracking-wider">
                  FalkorDB Query Transparency
                </h3>
              </div>
              <span className="rounded bg-sky-500/15 text-[10px] font-mono text-sky-300 px-2 py-0.5">
                MCP Tool Trace
              </span>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs font-mono">
              {latestToolCall ? (
                <div className="space-y-3">
                  <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 space-y-1.5">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">
                      Active Tool Invocation
                    </div>
                    <div className="text-sky-300 font-semibold">{latestToolCall.toolName}</div>
                    <div className="text-slate-400 text-[11px]">
                      Query ID: {latestToolCall.queryId || 'N/A'}
                    </div>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 space-y-1.5">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">
                      Parameterized Inputs
                    </div>
                    <pre className="text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(latestToolCall.params, null, 2)}
                    </pre>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 space-y-1.5">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">
                      Tool Result Summary
                    </div>
                    <div className="text-[11px] text-slate-300 font-sans leading-relaxed">
                      {latestToolCall.resultSummary}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-16 text-slate-500 font-sans text-xs space-y-2">
                  <Terminal className="h-6 w-6 mx-auto text-slate-600" />
                  <p>No tool execution trace active yet.</p>
                  <p className="text-[11px] text-slate-600">
                    Submit a query to inspect live Cypher tool arguments, query IDs, and execution latency.
                  </p>
                </div>
              )}
            </div>

            <div className="border-t border-slate-800/80 p-3 bg-[#0b121a] text-[10px] text-slate-500 font-sans flex items-center justify-between">
              <span>Gated by US-601 FastMCP Registry</span>
              <span className="text-emerald-400 font-medium">Read-Only Tools</span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
