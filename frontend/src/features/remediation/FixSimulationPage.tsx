import { FlaskConical, Layers, ShieldCheck, ShieldAlert } from 'lucide-react'
import { PlannedFeatureCard } from '@/shared/components/PlannedFeatureCard'

export function FixSimulationPage() {
  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold tracking-tight text-white">Fix Simulation</h1>
          <span className="rounded-full bg-amber-500/15 border border-amber-500/30 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-amber-300">
            US-502 &bull; Planned
          </span>
        </div>
        <p className="mt-1 text-xs text-slate-400">
          Simulate dependency upgrades on an isolated graph overlay to predict cleared paths, residual exposure, and introduced vulnerabilities.
        </p>
      </div>

      {/* Planned Feature Card with Backlog Acceptance Criteria */}
      <PlannedFeatureCard
        storyId="US-502"
        title="Fix Simulation via Ephemeral Graph Overlay"
        epic="E5: Remediation and Action"
        release="R2"
        persona="Security Administrator / Platform Engineer"
        description="Simulate what happens if a package version is upgraded or removed without mutating production graph state. Evaluates which reachability paths break, which exposure nodes disappear, and whether the candidate version introduces any newly published vulnerabilities."
        acceptanceCriteria={[
          'Runs on a scenario copy or overlay of the FalkorDB graph; the scenario never mutates real project graph data.',
          'Computes delta metrics: cleared findings count, unchanged findings count, and newly introduced vulnerabilities.',
          'Labels the simulation method clearly: metadata-driven simulation vs containerized sandbox verification.',
          'Predicts transitive dependency conflicts if the upgrade bumps shared sub-dependencies across service boundaries.',
        ]}
        backendRequirement="FalkorDB ephemeral branch or Cypher virtual graph projection overlay service to evaluate graph mutations in-memory."
      />

      {/* Architectural Simulation Preview */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-4">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <FlaskConical className="h-4 w-4 text-sky-400" />
          Planned Simulation Architecture & Delta Engine
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 space-y-2">
            <div className="flex items-center gap-2 text-emerald-400 font-semibold">
              <ShieldCheck className="h-4 w-4" />
              <span>1. Cleared Exposure</span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              Paths traversing the upgraded package version are severed. Upstream internet-facing services lose reachability to the known vulnerable CVE leaf.
            </p>
          </div>

          <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 space-y-2">
            <div className="flex items-center gap-2 text-slate-300 font-semibold">
              <Layers className="h-4 w-4" />
              <span>2. Residual Unchanged</span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              Vulnerabilities located on independent sub-graphs or alternate service dependency trees remain intact with their existing priority scores.
            </p>
          </div>

          <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 space-y-2">
            <div className="flex items-center gap-2 text-amber-400 font-semibold">
              <ShieldAlert className="h-4 w-4" />
              <span>3. Introduced Delta</span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              The target package version is automatically cross-referenced against OSV to ensure the patch version does not introduce fresh regression advisories.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
