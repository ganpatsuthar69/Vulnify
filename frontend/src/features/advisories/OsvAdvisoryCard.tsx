import { useState, useEffect, useCallback } from 'react'
import {
  ShieldAlert,
  ShieldCheck,
  Loader2,
  RefreshCw,
  AlertTriangle,
  AlertCircle,
  ExternalLink,
  Search,
  CheckCircle2,
  History,
} from 'lucide-react'
import { Link } from 'react-router'
import { importAdvisories, getProjectAdvisories, ProjectApiError } from '../projects/projectApi'
import type { OsvImportSummary, Project, ProjectAdvisory } from '../projects/types'

interface OsvAdvisoryCardProps {
  project: Project
}

export function OsvAdvisoryCard({ project }: OsvAdvisoryCardProps) {
  const [advisories, setAdvisories] = useState<ProjectAdvisory[]>([])
  const [summary, setSummary] = useState<OsvImportSummary | null>(null)
  const [isLoadingAdvisories, setIsLoadingAdvisories] = useState(false)
  const [isScanning, setIsScanning] = useState(false)
  const [forceRefresh, setForceRefresh] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadAdvisories = useCallback(async () => {
    setIsLoadingAdvisories(true)
    setError(null)
    try {
      const data = await getProjectAdvisories(project.id)
      setAdvisories(data)
    } catch (err) {
      if (err instanceof ProjectApiError) {
        setError(err.message)
      } else {
        setError('Failed to load project advisories.')
      }
    } finally {
      setIsLoadingAdvisories(false)
    }
  }, [project.id])

  useEffect(() => {
    void loadAdvisories()
    setSummary(null)
  }, [loadAdvisories])

  const handleScan = async () => {
    setIsScanning(true)
    setError(null)
    try {
      const result = await importAdvisories(project.id, forceRefresh)
      setSummary(result)
      await loadAdvisories()
    } catch (err) {
      if (err instanceof ProjectApiError) {
        setError(err.message)
      } else {
        setError('Failed to scan for OSV advisories.')
      }
    } finally {
      setIsScanning(false)
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return 'border-red-500/30 bg-red-500/10 text-red-300'
      case 'HIGH':
        return 'border-orange-500/30 bg-orange-500/10 text-orange-300'
      case 'MODERATE':
      case 'MEDIUM':
        return 'border-amber-500/30 bg-amber-500/10 text-amber-300'
      case 'LOW':
        return 'border-blue-500/30 bg-blue-500/10 text-blue-300'
      default:
        return 'border-slate-600 bg-slate-800 text-slate-300'
    }
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-sky-500/10 text-sky-400 ring-1 ring-sky-500/20">
            <ShieldAlert className="h-5 w-5" aria-hidden="true" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              OSV Advisory Ingestion
              {advisories.length > 0 && (
                <span className="rounded-full bg-red-500/20 border border-red-500/30 px-2 py-0.5 text-xs font-semibold text-red-300">
                  {advisories.length} advisory matches
                </span>
              )}
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Query official Open Source Vulnerabilities (OSV) API for package versions in this project.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={forceRefresh}
              onChange={(e) => setForceRefresh(e.target.checked)}
              disabled={isScanning}
              className="h-3.5 w-3.5 rounded border-slate-700 bg-slate-800 text-sky-500 focus:ring-sky-400 focus:ring-offset-slate-900"
            />
            <span>Bypass cache</span>
          </label>

          <button
            type="button"
            onClick={() => void handleScan()}
            disabled={isScanning}
            className="inline-flex items-center gap-2 rounded-lg border border-sky-500 bg-sky-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-sky-600/20 transition-all hover:bg-sky-500 disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            {isScanning ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                <span>Querying OSV...</span>
              </>
            ) : (
              <>
                <Search className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Scan for Advisories</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div
          role="alert"
          className="flex items-center justify-between rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-xs text-red-300"
        >
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 flex-shrink-0 text-red-400" aria-hidden="true" />
            <span>{error}</span>
          </div>
          <button
            type="button"
            onClick={() => void loadAdvisories()}
            className="inline-flex items-center gap-1 rounded bg-red-500/20 px-2 py-0.5 text-[11px] font-semibold text-red-200 hover:bg-red-500/30"
          >
            <RefreshCw className="h-3 w-3" aria-hidden="true" />
            <span>Retry</span>
          </button>
        </div>
      )}

      {/* Summary Statistics Card (from latest scan) */}
      {summary && (
        <div
          className={`rounded-xl border p-4 text-xs space-y-3 ${
            summary.status === 'completed'
              ? 'border-emerald-500/30 bg-emerald-500/5'
              : summary.status === 'partial_failure'
                ? 'border-amber-500/30 bg-amber-500/5'
                : 'border-red-500/30 bg-red-500/5'
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {summary.status === 'completed' ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-400" aria-hidden="true" />
              ) : (
                <AlertTriangle className="h-4 w-4 text-amber-400" aria-hidden="true" />
              )}
              <span className="font-semibold text-white">
                {summary.status === 'completed'
                  ? 'OSV Ingestion Completed'
                  : summary.status === 'partial_failure'
                    ? 'OSV Ingestion Completed with Partial Warnings'
                    : 'OSV Ingestion Notice'}
              </span>
            </div>
            <span className="font-mono text-[11px] text-slate-400">
              {summary.duration_ms.toFixed(1)} ms
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 border-t border-slate-800/60">
            <div className="rounded-lg bg-slate-900/50 p-2.5 border border-slate-800">
              <div className="text-[11px] text-slate-400">Packages Evaluated</div>
              <div className="text-base font-bold text-white mt-0.5">
                {summary.total_package_versions}
              </div>
              <div className="text-[10px] text-slate-500">
                {summary.unique_lookups} unique queries
              </div>
            </div>

            <div className="rounded-lg bg-slate-900/50 p-2.5 border border-slate-800">
              <div className="text-[11px] text-slate-400">Cache Hits</div>
              <div className="text-base font-bold text-sky-400 mt-0.5">
                {summary.cache_hits}
              </div>
              <div className="text-[10px] text-slate-500">
                {summary.unique_lookups > 0
                  ? `${Math.round((summary.cache_hits / summary.unique_lookups) * 100)}% hit rate`
                  : '0% hit rate'}
              </div>
            </div>

            <div className="rounded-lg bg-slate-900/50 p-2.5 border border-slate-800">
              <div className="text-[11px] text-slate-400">Advisories Found</div>
              <div
                className={`text-base font-bold mt-0.5 ${
                  summary.advisories_found > 0 ? 'text-amber-400' : 'text-emerald-400'
                }`}
              >
                {summary.advisories_found}
              </div>
              <div className="text-[10px] text-slate-500">
                {summary.advisories_created} new persisted
              </div>
            </div>

            <div className="rounded-lg bg-slate-900/50 p-2.5 border border-slate-800">
              <div className="text-[11px] text-slate-400">Clean Packages</div>
              <div className="text-base font-bold text-emerald-400 mt-0.5">
                {summary.packages_with_no_advisories}
              </div>
              <div className="text-[10px] text-slate-500">
                {summary.failed_lookups > 0 ? `${summary.failed_lookups} lookups failed` : '0 errors'}
              </div>
            </div>
          </div>

          {summary.errors && summary.errors.length > 0 && (
            <div className="rounded-lg bg-amber-500/10 border border-amber-500/20 p-2 text-[11px] text-amber-300 space-y-1">
              <div className="font-semibold">Notice:</div>
              {summary.errors.map((err, idx) => (
                <div key={idx}>• {err}</div>
              ))}
            </div>
          )}

          <div className="flex justify-end pt-1">
            <Link
              to="/history"
              className="inline-flex items-center gap-1.5 text-xs text-sky-400 hover:text-sky-300 font-medium transition-colors"
            >
              <History className="h-3.5 w-3.5" />
              <span>View run in Ingestion History &rarr;</span>
            </Link>
          </div>
        </div>
      )}

      {/* Advisories Table / List */}
      <div>
        <div className="flex items-center justify-between pb-3">
          <h4 className="text-sm font-semibold text-white">Detected Security Advisories</h4>
          <span className="text-xs text-slate-400">
            {advisories.length} {advisories.length === 1 ? 'advisory' : 'advisories'} linked in FalkorDB
          </span>
        </div>

        {isLoadingAdvisories ? (
          <div className="flex items-center justify-center p-8 text-slate-400">
            <Loader2 className="h-5 w-5 animate-spin text-sky-400 mr-2" />
            <span className="text-xs">Loading advisories...</span>
          </div>
        ) : advisories.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-800 bg-slate-900/30 p-8 text-center">
            <ShieldCheck className="h-8 w-8 text-slate-600 mx-auto" aria-hidden="true" />
            <p className="mt-2 text-xs font-semibold text-slate-300">
              No vulnerability advisories detected yet
            </p>
            <p className="mt-1 text-[11px] text-slate-500 max-w-md mx-auto">
              Click &quot;Scan for Advisories&quot; above to look up all imported package versions in the OSV database.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {advisories.map((adv) => (
              <div
                key={`${adv.package_version_id}:${adv.id}`}
                className="rounded-lg border border-slate-800/80 bg-slate-900/40 p-4 transition-colors hover:border-slate-700 space-y-2"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={`inline-flex items-center rounded px-2 py-0.5 text-[10px] font-bold tracking-wide uppercase border ${getSeverityBadgeClass(
                        adv.severity,
                      )}`}
                    >
                      {adv.severity}
                    </span>
                    <span className="font-mono text-xs font-bold text-white">{adv.id}</span>
                    {adv.aliases &&
                      adv.aliases.map((alias) => (
                        <span
                          key={alias}
                          className="rounded bg-slate-800 border border-slate-700 px-1.5 py-0.5 font-mono text-[10px] text-slate-300"
                        >
                          {alias}
                        </span>
                      ))}
                  </div>

                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-slate-400">Affected:</span>
                    <span className="font-mono text-sky-300">
                      {adv.package_name}@{adv.package_version}
                    </span>
                    {adv.source_url && (
                      <a
                        href={adv.source_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-sky-400 hover:text-sky-300 transition-colors ml-2"
                      >
                        <span className="text-[11px]">OSV</span>
                        <ExternalLink className="h-3 w-3" aria-hidden="true" />
                      </a>
                    )}
                  </div>
                </div>

                <p className="text-xs text-slate-300 line-clamp-2">
                  {adv.summary || 'No summary provided.'}
                </p>

                {adv.cvss && (
                  <div className="text-[10px] font-mono text-slate-400">
                    CVSS: <span className="text-slate-300">{adv.cvss}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Honest architectural notice */}
      <div className="rounded-lg border border-slate-800/60 bg-slate-900/20 p-3 text-[11px] text-slate-400 flex items-start gap-2">
        <AlertTriangle className="h-3.5 w-3.5 text-slate-400 flex-shrink-0 mt-0.5" aria-hidden="true" />
        <span>
          Paths and advisory links indicate architectural exposure, not proof of exploitability. &quot;No advisories found&quot; is not an absolute guarantee of safety.
        </span>
      </div>
    </div>
  )
}
