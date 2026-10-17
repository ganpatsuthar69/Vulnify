import { Database } from 'lucide-react'
import { PlannedFeatureCard } from '@/shared/components/PlannedFeatureCard'

export function InvestigationHistoryPage() {
  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold tracking-tight text-white">Investigation History & Stored Traces</h1>
          <span className="rounded-full bg-amber-500/15 border border-amber-500/30 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-amber-300">
            US-603 &bull; Planned
          </span>
        </div>
        <p className="mt-1 text-xs text-slate-400">
          Persistent audit record of agent reasoning sessions, Cypher tool calls, and grounded decision transcripts.
        </p>
      </div>

      {/* Planned Feature Card */}
      <PlannedFeatureCard
        storyId="US-603"
        title="Stored Investigation Traces & Session Replay"
        epic="E6: Agent"
        release="R1"
        persona="Security Auditor / Team Lead"
        description="Every agent investigation session is persisted as an AgentRun entity containing exact user prompts, intermediate tool calls, parameterized Cypher query identifiers, execution durations, and generated markdown conclusions."
        acceptanceCriteria={[
          'Each investigation run is stored with tool calls, inputs, result summaries, and query identifiers.',
          'Past runs can be reopened, searched by finding ID or package name, and inspected in a side-by-side drawer.',
          'Trace records cannot be modified or deleted; they form an immutable security decision audit trail.',
          'Protected by authentication: users can view only investigation traces corresponding to authorized projects.',
        ]}
        backendRequirement="AgentRun persistence schema and endpoint GET /api/investigations/{run_id}/trace in FalkorDB or relational store."
      />

      {/* Planned Schema Preview */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-4">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Database className="h-4 w-4 text-sky-400" />
          Planned AgentRun Trace Contract Specification
        </h3>
        <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-xs font-mono text-slate-300 leading-relaxed overflow-x-auto">
          {`interface AgentRunRecord {
  run_id: string;
  project_id: string;
  user_email: string;
  started_at: number;
  completed_at: number;
  initial_query: string;
  final_answer: string;
  tool_invocations: Array<{
    step: number;
    tool_name: "find_exposure_paths" | "check_fixed_versions" | "rank_priorities";
    query_id: string;
    params: Record<string, unknown>;
    result_count: number;
    duration_ms: number;
  }>;
}`}
        </div>
      </div>
    </div>
  )
}
