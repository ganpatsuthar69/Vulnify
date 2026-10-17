import { AlertCircle, Clock } from 'lucide-react'

interface PlannedFeatureCardProps {
  storyId: string
  title: string
  epic: string
  release: 'R1' | 'R2' | 'R3'
  persona: string
  description: string
  acceptanceCriteria: string[]
  backendRequirement?: string
}

export function PlannedFeatureCard({
  storyId,
  title,
  epic,
  release,
  persona,
  description,
  acceptanceCriteria,
  backendRequirement,
}: PlannedFeatureCardProps) {
  return (
    <div className="space-y-6">
      {/* Planned Feature Banner */}
      <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-5 text-amber-200">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Clock className="h-5 w-5 text-amber-400 shrink-0" aria-hidden="true" />
            <div>
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-amber-300">
                {storyId} &bull; {release} Planned Scope
              </span>
              <h2 className="text-base font-bold text-white">{title}</h2>
            </div>
          </div>
          <span className="rounded-full bg-amber-500/20 border border-amber-500/40 px-3 py-1 text-xs font-semibold text-amber-300 w-fit">
            Backlog Planned
          </span>
        </div>
        <p className="mt-3 text-xs text-amber-200/90 leading-relaxed">
          This feature is scheduled in the Vulnify product roadmap ({release}). In accordance with Vulnify
          safety and honesty rules, nonfunctional placeholder controls are not displayed until corresponding
          backend queries and validation services are complete.
        </p>
      </div>

      {/* Story Metadata & Spec */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-5">
        <div className="flex flex-wrap items-center gap-3 text-xs">
          <span className="rounded bg-slate-800 px-2.5 py-1 text-slate-300 font-medium">
            <strong>Epic:</strong> {epic}
          </span>
          <span className="rounded bg-slate-800 px-2.5 py-1 text-slate-300 font-medium">
            <strong>Persona:</strong> {persona}
          </span>
          <span className="rounded bg-slate-800 px-2.5 py-1 text-slate-300 font-medium">
            <strong>Release Target:</strong> {release}
          </span>
        </div>

        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            User Story Description
          </h3>
          <p className="mt-1.5 text-sm text-slate-200 leading-relaxed">{description}</p>
        </div>

        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Verified Acceptance Criteria
          </h3>
          <ul className="mt-2.5 space-y-2 text-xs text-slate-300">
            {acceptanceCriteria.map((criterion, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-sky-400 mt-1.5 shrink-0" />
                <span>{criterion}</span>
              </li>
            ))}
          </ul>
        </div>

        {backendRequirement && (
          <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-xs">
            <div className="flex items-center gap-2 font-semibold text-slate-200 mb-1">
              <AlertCircle className="h-4 w-4 text-sky-400" aria-hidden="true" />
              <span>Backend Prerequisite</span>
            </div>
            <p className="text-slate-400">{backendRequirement}</p>
          </div>
        )}

        <div className="border-t border-slate-800/80 pt-4 text-xs text-slate-400 flex items-center justify-between">
          <span>Referenced in Vulnify Product Backlog</span>
          <span className="font-mono text-[11px] text-slate-500">{storyId}</span>
        </div>
      </div>
    </div>
  )
}
