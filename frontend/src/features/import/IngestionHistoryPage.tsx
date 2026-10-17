import { History } from 'lucide-react'
import { PlannedFeatureCard } from '@/shared/components/PlannedFeatureCard'

export function IngestionHistoryPage() {
  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-bold tracking-tight text-white">Ingestion History & Audit Log</h1>
          <span className="rounded-full bg-amber-500/15 border border-amber-500/30 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-amber-300">
            US-105 &bull; Planned
          </span>
        </div>
        <p className="mt-1 text-xs text-slate-400">
          Historical timeline of lockfile uploads, OSV synchronization runs, SHA-256 integrity digests, and pipeline traces.
        </p>
      </div>

      {/* Planned Feature Card */}
      <PlannedFeatureCard
        storyId="US-105"
        title="Ingestion Job History & Artifact Provenance Log"
        epic="E1: Graph Ingestion"
        release="R2"
        persona="DevSecOps Engineer / Compliance Officer"
        description="Every lockfile upload, service topology import, and OSV synchronization run is permanently logged with timestamp, SHA-256 file checksum, operator identity, graph mutation counts, and execution warnings."
        acceptanceCriteria={[
          'Lists all past lockfile imports with filename, service name, SHA-256 hash, and execution duration.',
          'Records packages created vs packages reused to track incremental graph population.',
          'Captures OSV synchronization batches, cache hit ratios, and upstream rate limit warnings.',
          'Provides one-click export of ingestion provenance records for compliance auditing.',
        ]}
        backendRequirement="Persistent IngestionJob repository with endpoint GET /api/projects/{project_id}/jobs."
      />

      {/* Planned Audit Log Schema Preview */}
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-4">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <History className="h-4 w-4 text-sky-400" />
          Planned Ingestion Record Schema
        </h3>
        <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-4 text-xs font-mono text-slate-300 leading-relaxed overflow-x-auto">
          {`interface IngestionJobRecord {
  job_id: string;
  project_id: string;
  job_type: "lockfile_import" | "osv_sync" | "version_matching";
  filename: string;
  sha256_hash: string;
  service_name: string;
  packages_parsed: number;
  packages_created: number;
  packages_reused: number;
  advisories_matched: number;
  duration_ms: number;
  status: "completed" | "partial_failure" | "failed";
  errors: string[];
  created_at: number;
}`}
        </div>
      </div>
    </div>
  )
}
