import { useState } from 'react'
import {
  AlertTriangle,
  Clock,
  Network,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from 'lucide-react'
import { Link } from 'react-router'
import type { DataQualityWarning, DataQualityCategory } from '@/features/projects/types'

interface DataQualityBannerProps {
  warnings: DataQualityWarning[]
  className?: string
  defaultExpanded?: boolean
}

export function DataQualityBanner({
  warnings,
  className = '',
  defaultExpanded = true,
}: DataQualityBannerProps) {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded)

  if (!warnings || warnings.length === 0) {
    return null
  }

  const getCategoryMeta = (category: DataQualityCategory) => {
    switch (category) {
      case 'missing_topology':
        return {
          icon: Network,
          label: 'Topology Incomplete',
          badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
          borderClass: 'border-amber-500/30',
        }
      case 'stale_advisory_data':
        return {
          icon: Clock,
          label: 'Advisory Freshness',
          badgeClass: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
          borderClass: 'border-orange-500/30',
        }
      case 'partial_import':
        return {
          icon: AlertTriangle,
          label: 'Incomplete Ingestion',
          badgeClass: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
          borderClass: 'border-rose-500/30',
        }
      case 'no_path':
      default:
        return {
          icon: ShieldAlert,
          label: 'Path Caveat',
          badgeClass: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
          borderClass: 'border-sky-500/30',
        }
    }
  }

  const hasHighSeverity = warnings.some(
    (w) => w.severity === 'warning' || w.severity === 'error',
  )

  return (
    <div
      role="region"
      aria-label="Data Quality Warnings and Analysis Limits"
      className={`rounded-xl border ${
        hasHighSeverity
          ? 'border-amber-500/40 bg-[#16120d]'
          : 'border-slate-800 bg-[#0f1822]'
      } p-4 shadow-lg text-xs ${className}`}
    >
      {/* Header bar */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <AlertTriangle
            className={`h-4 w-4 shrink-0 ${
              hasHighSeverity ? 'text-amber-400' : 'text-slate-400'
            }`}
            aria-hidden="true"
          />
          <div>
            <span className="font-bold text-white text-sm">
              Data Quality &amp; Analysis Scope Warnings
            </span>
            <span className="ml-2 rounded-full bg-amber-400/20 px-2 py-0.5 text-[10px] font-semibold text-amber-300">
              {warnings.length} {warnings.length === 1 ? 'Notice' : 'Notices'}
            </span>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setIsExpanded(!isExpanded)}
          className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors focus:outline-none focus:ring-1 focus:ring-sky-500"
          aria-expanded={isExpanded}
          aria-controls="data-quality-warnings-list"
        >
          <span className="text-[11px] font-medium">
            {isExpanded ? 'Hide Details' : 'Show Details'}
          </span>
          {isExpanded ? (
            <ChevronUp className="h-3.5 w-3.5" aria-hidden="true" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
          )}
        </button>
      </div>

      {/* Safety Motto Summary */}
      <p className="mt-1.5 text-slate-400 text-[11px] leading-relaxed">
        <strong className="text-slate-300">Analysis Safety Guarantee:</strong> Vulnify reports
        proven architectural exposure. Missing graph facts, stale advisories, or unlinked services
        limit analysis scope and must never be mistaken for proof of safety.
      </p>

      {/* Expandable Warnings List */}
      {isExpanded && (
        <div id="data-quality-warnings-list" className="mt-3.5 space-y-2.5 border-t border-slate-800/80 pt-3">
          {warnings.map((w, idx) => {
            const meta = getCategoryMeta(w.category)
            const Icon = meta.icon

            return (
              <div
                key={`${w.code}-${idx}`}
                className="rounded-lg border border-slate-800/90 bg-[#0b121a]/90 p-3 flex flex-col sm:flex-row sm:items-start justify-between gap-3"
              >
                <div className="flex items-start gap-2.5">
                  <Icon
                    className="h-4 w-4 shrink-0 text-amber-400 mt-0.5"
                    aria-hidden="true"
                  />
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-slate-200 text-xs">
                        {w.title}
                      </span>
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] font-mono border ${meta.badgeClass}`}
                      >
                        {meta.label}
                      </span>
                    </div>
                    <p className="text-slate-400 text-[11px] leading-relaxed">
                      {w.message}
                    </p>
                  </div>
                </div>

                {/* Contextual Action Link */}
                {w.category === 'partial_import' && (
                  <Link
                    to="/imports"
                    className="shrink-0 inline-flex items-center gap-1 rounded bg-slate-800 px-2.5 py-1 text-[11px] font-medium text-sky-400 hover:text-sky-300 hover:bg-slate-700 transition-colors"
                  >
                    <span>View Import Jobs</span>
                    <ExternalLink className="h-3 w-3" aria-hidden="true" />
                  </Link>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
