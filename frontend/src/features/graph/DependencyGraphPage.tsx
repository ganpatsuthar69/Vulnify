import { useCallback, useMemo, useState, useRef } from 'react'
import { Link } from 'react-router'
import { AlertTriangle, Loader2, Network, RefreshCw, Search, Table2 } from 'lucide-react'
import type { ReactFlowInstance } from '@xyflow/react'
import { useProjects } from '@/features/projects/ProjectProvider'
import { ExplorerCanvas } from './ExplorerCanvas'
import type { CanvasNode } from './ExplorerNodeView'
import { GraphNodeInspector } from './GraphNodeInspector'
import { filterGraph, selectionPath } from './graphLayout'
import { useProjectGraph } from './useProjectGraph'
import { defaultFilters, type ExplorerNode, type GraphFilters } from './types'

const severities = ['all', 'critical', 'high', 'medium', 'low', 'unknown'] as const
const selectClass = 'rounded-lg border border-slate-700 bg-[#0f1822] px-2.5 py-1.5 text-xs text-slate-200 focus:border-sky-500 focus:outline-none'

export function DependencyGraphPage() {
  const { activeProject } = useProjects()
  const projectId = activeProject?.id ?? ''
  const { graph, loading, error, load, retry, loadMore } = useProjectGraph(projectId)
  const [filters, setFilters] = useState<GraphFilters>(defaultFilters)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [searchInput, setSearchInput] = useState('')
  const flow = useRef<ReactFlowInstance<CanvasNode> | null>(null)
  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const visible = useMemo(() => graph ? filterGraph(graph, filters) : null, [graph, filters])
  const selectedNode: ExplorerNode | null = graph?.nodes.find(node => node.id === selectedId) ?? null
  const highlightedEdgeIds = useMemo(() => {
    if (!graph || !selectedId) return new Set<string>()
    return new Set(selectionPath(graph, selectedId).map(edge => edge.id))
  }, [graph, selectedId])

  const runSearch = useCallback((term: string) => {
    setSearchInput(term)
    if (searchTimer.current) clearTimeout(searchTimer.current)
    searchTimer.current = setTimeout(() => void load(term.trim() ? { q: term.trim() } : {}), 300)
  }, [load])

  const expand = useCallback((nodeId: string) => {
    void load({ node_id: nodeId })
  }, [load])

  if (!activeProject) {
    return (
      <div className="rounded-xl border border-dashed border-slate-800 bg-[#0f1822] p-12 text-center text-xs text-slate-400">
        <h2 className="text-sm font-bold text-white">No Active Project Selected</h2>
        <p className="mt-1">Select or create a project in the top navigation bar to view its dependency graph.</p>
      </div>
    )
  }

  const packageCount = graph?.total_packages ?? 0
  const advisoryCount = graph?.total_advisories ?? 0

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 border-b border-slate-800 pb-4 xl:flex-row xl:items-center xl:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-bold text-white">Dependency Graph Explorer</h1>
            <span className="rounded-full border border-sky-500/30 bg-sky-500/20 px-2.5 py-0.5 text-xs font-semibold text-sky-300">
              {graph ? `${packageCount} verified packages • ${advisoryCount} linked advisories` : 'Loading project graph'}
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Project-scoped FalkorDB topology for <span className="font-semibold text-slate-200">{activeProject.name}</span>.
            Showing <span className="font-semibold text-slate-200">{visible?.nodes.length ?? 0}</span> of {graph?.nodes.length ?? 0} loaded nodes; counts reflect fetched, verified data only.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Graph toolbar">
          <label className="relative block"><span className="sr-only">Search packages and advisories</span>
            <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
            <input type="search" value={searchInput} onChange={event => runSearch(event.target.value)} placeholder="Search package or advisory…" className={`${selectClass} w-52 pl-8`} />
          </label>
          <label className="sr-only" htmlFor="graph-classification">Dependency type</label>
          <select id="graph-classification" className={selectClass} value={filters.classification} onChange={event => setFilters(f => ({ ...f, classification: event.target.value as GraphFilters['classification'] }))}>
            <option value="all">Direct &amp; transitive</option><option value="direct">Direct only</option><option value="transitive">Transitive only</option>
          </select>
          <label className="sr-only" htmlFor="graph-severity">Advisory severity</label>
          <select id="graph-severity" className={selectClass} value={filters.severity} onChange={event => setFilters(f => ({ ...f, severity: event.target.value }))}>
            {severities.map(value => <option key={value} value={value}>{value === 'all' ? 'All severities' : value}</option>)}
          </select>
          <label className="sr-only" htmlFor="graph-status">Affected status</label>
          <select id="graph-status" className={selectClass} value={filters.status} onChange={event => setFilters(f => ({ ...f, status: event.target.value as GraphFilters['status'] }))}>
            <option value="all">All packages</option><option value="affected">Affected only</option><option value="clean">Clean only</option>
          </select>
          <label className="sr-only" htmlFor="graph-mode">View mode</label>
          <select id="graph-mode" className={selectClass} value={filters.mode} onChange={event => setFilters(f => ({ ...f, mode: event.target.value as GraphFilters['mode'] }))}>
            <option value="combined">Dependencies + advisories</option><option value="dependencies">Dependencies only</option><option value="vulnerabilities">Vulnerabilities only</option>
          </select>
          <button type="button" onClick={() => flow.current?.fitView({ padding: 0.18, maxZoom: 1, duration: 220 })} className={`${selectClass} hover:bg-slate-800`}>Fit to view</button>
          <button type="button" onClick={() => { setSelectedId(null); setSearchInput(''); setFilters(defaultFilters); void load(); }} className={`${selectClass} inline-flex items-center gap-1.5 hover:bg-slate-800`}>
            <RefreshCw size={13} aria-hidden="true" />Reset
          </button>
          <Link to="/dependencies" className={`${selectClass} inline-flex items-center gap-1.5 text-sky-300 hover:bg-slate-800`}>
            <Table2 size={13} aria-hidden="true" />Package table view
          </Link>
        </div>
      </div>

      {error ? (
        <div role="alert" className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-8 text-center text-xs text-rose-200">
          <AlertTriangle className="mx-auto mb-2 h-7 w-7 text-rose-400" aria-hidden="true" />
          <p className="font-bold text-white">Could not load the project graph</p><p className="mt-1">{error}</p>
          <button type="button" onClick={retry} className="mt-3 rounded-lg bg-slate-800 px-3 py-1.5 font-semibold text-slate-200 hover:bg-slate-700">Retry</button>
        </div>
      ) : loading ? (
        <div role="status" className="flex h-[520px] flex-col items-center justify-center rounded-xl border border-slate-800 bg-[#0b121a] text-xs text-slate-300">
          <Loader2 className="h-7 w-7 animate-spin text-sky-400" aria-hidden="true" /><span className="mt-3">Loading verified relationships from FalkorDB…</span>
        </div>
      ) : graph && visible && visible.nodes.length === 0 ? (
        <div className="flex h-[420px] flex-col items-center justify-center rounded-xl border border-slate-800 bg-[#0b121a] p-8 text-center text-xs text-slate-400">
          <Network className="mb-2 h-8 w-8 text-slate-500" aria-hidden="true" />
          <h3 className="font-semibold text-white">{graph.nodes.length ? 'No nodes match these filters' : 'No graph nodes stored yet'}</h3>
          <p className="mt-1 max-w-sm">{graph.nodes.length ? 'Clear a filter or search term to inspect the real neighborhood.' : 'Import a lockfile to populate package nodes and dependency edges.'}</p>
          <Link to={graph.nodes.length ? '#graph-classification' : '/import'} className="mt-3 rounded-lg bg-sky-500 px-3 py-1.5 font-semibold text-slate-950 hover:bg-sky-400">{graph.nodes.length ? 'Open filters' : 'Import Data'}</Link>
        </div>
      ) : graph && visible ? (
        <>
          {(graph.warnings.length > 0 || !graph.counts_complete) && (
            <div role="status" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-[11px] leading-relaxed text-amber-200">
              <AlertTriangle className="mr-1.5 inline h-3.5 w-3.5" aria-hidden="true" />
              {[...new Set(graph.warnings)].join(' ')} {!graph.counts_complete && 'Counts reflect only the verified, bounded subset fetched for this view.'}
            </div>
          )}
          <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_330px]">
            <div className="min-w-0 space-y-3">
              <ExplorerCanvas nodes={visible.nodes} edges={visible.edges} context={visible.context} selectedId={selectedId} highlightedEdges={highlightedEdgeIds} onSelect={setSelectedId} onReady={instance => { flow.current = instance }} />
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[11px] text-slate-400" aria-label="Graph legend">
                <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full border border-sky-400 bg-sky-500/20" />Project / service root</span>
                <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full border border-slate-500 bg-[#101b29]" />Clean package</span>
                <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full border border-rose-400 bg-rose-500/20" />Affected package / advisory</span>
                <span className="flex items-center gap-1.5"><span className="h-0.5 w-5 bg-slate-500" />DEPENDS_ON →</span>
                <span className="flex items-center gap-1.5"><span className="h-0.5 w-5 bg-rose-400" />AFFECTS ← (advisory points to package)</span>
                <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full border border-sky-400 ring-1 ring-sky-400" />Selected path</span>
              </div>
              {graph.has_more && graph.next_offset !== null && (
                <button type="button" disabled={loading} onClick={() => void loadMore()} className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold text-sky-300 hover:bg-slate-800 disabled:opacity-50">
                  Load {filters.classification === 'all' && filters.severity === 'all' && filters.status === 'all' ? 'more dependencies' : 'more results'} from FalkorDB
                </button>
              )}
            </div>
            <GraphNodeInspector graph={graph} node={selectedNode} loading={loading} onSelect={setSelectedId} onExpand={expand} />
          </div>
        </>
      ) : null}
      <p className="text-[10px] leading-relaxed text-slate-400">Architectural exposure, not proof of exploitability. “No path found” and unanalyzed packages do not guarantee safety. Relationships shown come only from stored FalkorDB edges verified for this project.</p>
    </div>
  )
}
