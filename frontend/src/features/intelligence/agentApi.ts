/**
 * Agent Investigation API Client & SSE Stream Consumer (US-602).
 */

export type AgentStreamEventType =
  | 'run_started'
  | 'assistant_status'
  | 'tool_started'
  | 'tool_completed'
  | 'answer_delta'
  | 'answer_completed'
  | 'run_completed'
  | 'run_cancelled'
  | 'run_timeout'
  | 'run_step_limit'
  | 'run_failed'

export interface AgentStreamEvent {
  event: AgentStreamEventType
  run_id: string
  sequence: number
  timestamp: number
  data: Record<string, any>
}

export interface ToolStepInfo {
  callId: string
  toolName: string
  displayName: string
  inputs: Record<string, unknown>
  status: 'running' | 'completed' | 'error' | 'rejected'
  resultSummary?: string
  durationMs?: number
  outcome?: string
  evidenceReferences?: string[]
  queryId?: string
}

export interface AgentRunCancelResponse {
  run_id: string
  status: 'cancelling' | 'cancelled' | 'already_terminal' | 'not_found'
  message: string
}

export interface AgentRunStatusResponse {
  run_id: string
  project_id: string
  status: string
  step_count: number
  created_at: number
  completed_at?: number | null
  error_message?: string | null
}

export interface StreamInvestigationParams {
  projectId: string
  message: string
  signal?: AbortSignal
  onEvent: (event: AgentStreamEvent) => void
  onError?: (error: Error) => void
}

/**
 * Consumes the agent Server-Sent Events stream incrementally over POST /api/agent/chat/stream.
 */
export async function streamAgentInvestigation({
  projectId,
  message,
  signal,
  onEvent,
  onError,
}: StreamInvestigationParams): Promise<void> {
  try {
    const response = await fetch('/api/agent/chat/stream', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'vulnify',
      },
      credentials: 'include',
      body: JSON.stringify({
        project_id: projectId,
        message,
      }),
      signal,
    })

    if (!response.ok) {
      let errorMsg = `Server error ${response.status}`
      try {
        const errJson = await response.json()
        errorMsg = errJson.detail || errJson.message || errorMsg
      } catch {
        // Fallback to HTTP status text
      }
      throw new Error(errorMsg)
    }

    if (!response.body) {
      throw new Error('Streaming response body unavailable')
    }

    const reader = response.body.getReader()
    const decoder = new TextDecoder('utf-8')
    let buffer = ''

    while (true) {
      const { done, value } = await reader.read()
      if (done) break

      buffer += decoder.decode(value, { stream: true })

      // Split SSE message frames on double newline
      const parts = buffer.split('\n\n')
      buffer = parts.pop() || ''

      for (const part of parts) {
        const trimmed = part.trim()
        if (!trimmed) continue

        const lines = trimmed.split('\n')
        let dataStr = ''

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            dataStr = line.slice(6)
          } else if (line.startsWith('data:')) {
            dataStr = line.slice(5)
          }
        }

        if (dataStr) {
          try {
            const parsedEvent = JSON.parse(dataStr) as AgentStreamEvent
            onEvent(parsedEvent)
          } catch (parseErr) {
            console.warn('Failed to parse SSE frame as JSON:', dataStr, parseErr)
          }
        }
      }
    }

    // Process any trailing buffer
    if (buffer.trim()) {
      const lines = buffer.trim().split('\n')
      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const parsedEvent = JSON.parse(line.slice(6)) as AgentStreamEvent
            onEvent(parsedEvent)
          } catch {
            // Ignore trailing malformed text
          }
        }
      }
    }
  } catch (err: any) {
    if (err.name === 'AbortError') {
      // Stream aborted by client
      return
    }
    if (onError) {
      onError(err instanceof Error ? err : new Error(String(err)))
    } else {
      throw err
    }
  }
}

/**
 * Request server-side cancellation of an active agent run.
 */
export async function cancelAgentRun(runId: string): Promise<AgentRunCancelResponse> {
  const response = await fetch(`/api/agent/runs/${encodeURIComponent(runId)}/cancel`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'vulnify',
    },
    credentials: 'include',
  })

  if (!response.ok) {
    let errorMsg = `Cancellation failed (${response.status})`
    try {
      const errJson = await response.json()
      errorMsg = errJson.detail || errJson.message || errorMsg
    } catch {
      // Ignore
    }
    throw new Error(errorMsg)
  }

  return response.json()
}

/**
 * Retrieve current status of an agent run.
 */
export async function getAgentRunStatus(runId: string): Promise<AgentRunStatusResponse> {
  const response = await fetch(`/api/agent/runs/${encodeURIComponent(runId)}/status`, {
    headers: {
      'X-Requested-With': 'vulnify',
    },
    credentials: 'include',
  })

  if (!response.ok) {
    throw new Error(`Failed to fetch run status (${response.status})`)
  }

  return response.json()
}

// =====================================================================
// US-603: Stored Traces & Investigation History API
// =====================================================================

export interface AgentRunSummary {
  id: string
  project_id: string
  user_email: string
  prompt: string
  status: string
  started_at: number
  completed_at?: number | null
  has_final_answer: boolean
  step_count: number
  tool_call_count: number
  error_message?: string | null
}

export interface AgentRunDetail {
  id: string
  project_id: string
  user_id: string
  user_email: string
  prompt: string
  status: string
  started_at: number
  completed_at?: number | null
  final_answer?: string | null
  error_message?: string | null
  step_count: number
  findings_referenced: string[]
  paths_referenced: string[]
  tool_call_count: number
}

export interface AgentToolCallDetail {
  id: string
  run_id: string
  sequence: number
  tool_name: string
  display_name?: string | null
  inputs: Record<string, unknown>
  result_summary: string
  status: 'running' | 'success' | 'error' | 'rejected'
  query_id?: string | null
  duration_ms?: number | null
  outcome?: string | null
  evidence_references: string[]
  started_at: number
  completed_at?: number | null
  error_message?: string | null
}

export interface AgentRunTraceResponse {
  run: AgentRunDetail
  tool_calls: AgentToolCallDetail[]
}

export interface AgentRunListResponse {
  items: AgentRunSummary[]
  total: number
  page: number
  page_size: number
}

/**
 * List historical agent investigation runs for a project (US-603).
 */
export async function listAgentRuns(
  projectId: string,
  page = 1,
  pageSize = 25,
): Promise<AgentRunListResponse> {
  const query = new URLSearchParams({
    project_id: projectId,
    page: String(page),
    page_size: String(pageSize),
  })

  const response = await fetch(`/api/agent/runs?${query.toString()}`, {
    headers: {
      'X-Requested-With': 'vulnify',
    },
    credentials: 'include',
  })

  if (!response.ok) {
    let errorMsg = `Failed to list investigation runs (${response.status})`
    try {
      const err = await response.json()
      errorMsg = err.detail || err.message || errorMsg
    } catch {
      // Fallback
    }
    throw new Error(errorMsg)
  }

  return response.json()
}

/**
 * Retrieve single agent run metadata and final answer (US-603).
 */
export async function getAgentRun(runId: string): Promise<AgentRunDetail> {
  const response = await fetch(`/api/agent/runs/${encodeURIComponent(runId)}`, {
    headers: {
      'X-Requested-With': 'vulnify',
    },
    credentials: 'include',
  })

  if (!response.ok) {
    throw new Error(`Failed to fetch run details for '${runId}' (${response.status})`)
  }

  return response.json()
}

/**
 * Retrieve full execution trace including ordered tool calls (US-603).
 */
export async function getAgentRunTrace(runId: string): Promise<AgentRunTraceResponse> {
  const response = await fetch(`/api/agent/runs/${encodeURIComponent(runId)}/trace`, {
    headers: {
      'X-Requested-With': 'vulnify',
    },
    credentials: 'include',
  })

  if (!response.ok) {
    let errorMsg = `Failed to fetch execution trace for '${runId}' (${response.status})`
    try {
      const err = await response.json()
      errorMsg = err.detail || err.message || errorMsg
    } catch {
      // Fallback
    }
    throw new Error(errorMsg)
  }

  return response.json()
}

/**
 * Find agent runs that referenced a specific finding ID (US-603).
 */
export async function getAgentRunsByFinding(
  projectId: string,
  findingId: string,
  limit = 10,
): Promise<AgentRunSummary[]> {
  const query = new URLSearchParams({
    project_id: projectId,
    limit: String(limit),
  })

  const response = await fetch(
    `/api/agent/runs/by-finding/${encodeURIComponent(findingId)}?${query.toString()}`,
    {
      headers: {
        'X-Requested-With': 'vulnify',
      },
      credentials: 'include',
    },
  )

  if (!response.ok) {
    let errorMsg = `Failed to find runs for finding '${findingId}' (${response.status})`
    try {
      const err = await response.json()
      errorMsg = err.detail || err.message || errorMsg
    } catch {
      // Fallback
    }
    throw new Error(errorMsg)
  }

  return response.json()
}

