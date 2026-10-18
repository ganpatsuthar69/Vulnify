import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import { Eye, Loader2, Route } from 'lucide-react'
import { getProjectExposurePaths } from '@/features/projects/projectApi'
import type { ProjectExposurePathsResponse } from '@/features/projects/types'
import type { ExplorerGraph, ExplorerNode } from './types'
import { propertyText, selectionPath } from './graphLayout'

interface Props {
  graph: ExplorerGraph
  node: ExplorerNode | null
  loading: boolean
  onSelect: (id: string) => void
  onExpand: (id: string) => void
}

function referenceUrls(value: unknown): string[] {
  const values = Array.isArray(value) ? value : value ? [value] : []
  return values.flatMap(item => {
    const url = typeof item === 'string' ? item : typeof item === 'object' && item !== null && 'url' in item ? item.url : null
    return typeof url === 'string' && /^https?:\/\//i.test(url) ? [url] : []
  })
}

export function GraphNodeInspector({ graph, node, loading, onSelect, onExpand }: Props) {
  const [exposure, setExposure] = useState<ProjectExposurePathsResponse | null>(null)
  const [explaining, setExplaining] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const requestId = useRef(0)
  useEffect(() => () => { requestId.current += 1 }, [])
  useEffect(() => {
    requestId.current += 1
    setExposure(null); setError(null); setExplaining(false)
  }, [node?.id, graph.project_id])

  const connected = node ? graph.edges.filter(edge => edge.source === node.id || edge.target === node.id) : []
  const dependencies = connected.filter(edge => edge.relationship_type === 'DEPENDS_ON')
  const advisories = connected.filter(edge => edge.relationship_type === 'AFFECTS')
  const findings = [...new Set(advisories.flatMap(edge => Array.isArray(edge.properties.finding_ids) ? edge.properties.finding_ids.filter((id): id is string => typeof id === 'string') : []))]
  const [chosenFinding, setChosenFinding] = useState('')
  const findingId = findings.includes(chosenFinding) ? chosenFinding : findings[0]
  const path = node ? selectionPath(graph, node.id) : []
  const byId = new Map(graph.nodes.map(item => [item.id, item]))
  const fields = node?.node_type === 'package'
    ? ['name', 'version', 'ecosystem', 'purl']
    : node?.node_type === 'advisory'
      ? ['id', 'source', 'severity', 'cvss', 'summary', 'affected_ranges']
      : ['name', 'ecosystem', 'internet_facing']
  const references = node ? [...new Set([...referenceUrls(node.properties.references), ...referenceUrls(node.properties.source_url)])] : []

  async function explain() {
    if (!findingId) return
    const current = ++requestId.current
    setExplaining(true); setError(null); setExposure(null)
    try {
      const result = await getProjectExposurePaths(graph.project_id, { findingId, limit: 5 })
      if (current === requestId.current) setExposure(result)
    } catch (failure) {
      if (current === requestId.current) setError(failure instanceof Error ? failure.message : 'Exposure analysis failed.')
    } finally {
      if (current === requestId.current) setExplaining(false)
    }
  }

  return (
    <aside className="min-w-0 space-y-4 rounded-xl border border-slate-800 bg-[#0f1822] p-4 text-xs text-slate-300 xl:max-h-[700px] xl:overflow-y-auto" aria-label="Node Inspector">
      <h2 className="flex items-center gap-2 border-b border-slate-800 pb-3 text-sm font-bold text-white"><Eye size={16} className="text-sky-400" />Node Inspector</h2>
      {!node ? <p className="py-10 text-center leading-relaxed text-slate-400">Select a node to inspect its recorded properties, connected dependencies, and evidence path.</p> : <>
        <div><span className="text-[10px] uppercase tracking-wider text-sky-300">{node.classification ?? node.node_type}</span><h3 className="mt-1 break-all font-mono text-sm font-bold text-white">{node.label}</h3></div>
        <dl className="space-y-2 rounded-lg bg-[#0b121a] p-3">
          {fields.map(field => <div key={field}><dt className="capitalize text-slate-400">{field.replaceAll('_', ' ')}</dt><dd className="mt-0.5 max-h-32 overflow-auto break-words font-mono text-[11px]">{propertyText(node.properties[field])}</dd></div>)}
          {node.node_type === 'package' && <div><dt className="text-slate-400">Verified advisories</dt><dd>{node.advisory_count}{!graph.counts_complete ? ' (verified subset)' : ''}</dd></div>}
        </dl>
        <p className="text-[10px] leading-relaxed text-slate-400">Properties above are loaded. “Not recorded” means absent in storage. Neighbor lists below cover loaded edges only; expand to retrieve more.</p>
        <button type="button" disabled={loading} onClick={() => onExpand(node.id)} className="w-full rounded-lg border border-sky-500/40 bg-sky-500/10 px-3 py-2 font-semibold text-sky-200 hover:bg-sky-500/20 disabled:opacity-50">Expand neighborhood</button>
        <section className="space-y-2"><h4 className="font-semibold text-white">Dependency relationships · {dependencies.length} loaded</h4>
          {dependencies.length === 0 && <p className="text-slate-400">No dependency relationships loaded for this node.</p>}
          <ul className="max-h-40 space-y-1 overflow-auto">{dependencies.map(edge => {
            const other = edge.source === node.id ? edge.target : edge.source
            return <li key={edge.id}><button type="button" onClick={() => onSelect(other)} className="w-full rounded border border-slate-800 p-2 text-left hover:border-sky-500"><span className="text-sky-300">{edge.source === node.id ? 'Outgoing → ' : 'Incoming ← '}</span>{byId.get(other)?.label}</button></li>
          })}</ul>
        </section>
        <section className="space-y-2"><h4 className="font-semibold text-white">{node.node_type === 'advisory' ? 'Affected package versions' : 'Linked verified advisories'} · {advisories.length} loaded</h4>
          <ul className="max-h-48 space-y-2 overflow-auto">{advisories.map(edge => {
            const other = node.node_type === 'advisory' ? edge.target : edge.source
            return <li key={edge.id} className="rounded border border-slate-800 p-2"><button type="button" className="break-all text-left text-sky-300 hover:underline" onClick={() => onSelect(other)}>{byId.get(other)?.label}</button><p className="mt-1 text-[10px]">AFFECTS · {propertyText(edge.properties.reason)}</p><p className="mt-1 text-[10px] text-slate-400">Range: {propertyText(edge.properties.matched_range)} · Fixed version: {propertyText(edge.properties.fixed_version)}</p></li>
          })}</ul>
          {advisories.length === 0 && <p className="text-slate-400">None loaded. This is not a guarantee of safety.</p>}
        </section>
        <section className="space-y-2 rounded-lg border border-sky-500/20 bg-sky-500/5 p-3"><h4 className="flex items-center gap-1.5 font-semibold text-sky-200"><Route size={14} />Root evidence path</h4>
          {path.length ? <ol className="space-y-2 text-[11px]">
            <li>{byId.get(graph.root_id)?.label}</li>
            {path.map(edge => <li key={edge.id} className="break-words"><span className="text-sky-300">{edge.relationship_type === 'AFFECTS' ? '← AFFECTS — ' : `→ ${edge.relationship_type} — `}</span>{byId.get(edge.relationship_type === 'AFFECTS' ? edge.source : edge.target)?.label}</li>)}
          </ol> : <p className="text-slate-400">{node.id === graph.root_id ? 'This is the selected project root.' : 'No verified root path is loaded. Expand this neighborhood; no path does not guarantee safety.'}</p>}
          {node.node_type === 'advisory' && <p className="text-[10px] text-slate-400">AFFECTS points from advisory to package. It is not a dependency step.</p>}
        </section>
        {findings.length > 1 && <label className="block space-y-1 text-slate-400">Finding to explain<select aria-label="Finding to explain" value={findingId} onChange={event => { setChosenFinding(event.target.value); requestId.current += 1; setExposure(null); setError(null); setExplaining(false) }} className="w-full rounded border border-slate-700 bg-[#0b121a] p-2 text-slate-200">{findings.map(id => <option key={id} value={id}>{id}</option>)}</select></label>}
        {findingId ? <button type="button" disabled={explaining} onClick={() => void explain()} className="flex w-full items-center justify-center gap-2 rounded-lg bg-sky-500 px-3 py-2 font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-50">{explaining && <Loader2 size={14} className="animate-spin" />}Explain exposure</button> : <p className="text-[10px] text-slate-400">Exposure analysis needs a verified advisory finding. Expand an affected package to load one.</p>}
        {error && <p role="alert" className="text-rose-300">{error} Try Explain exposure again.</p>}
        {exposure && <section aria-label="Exposure evidence" className="space-y-2 rounded-lg border border-slate-700 p-3">
          <h4 className="font-semibold text-white">Backend exposure evidence</h4><p>Topology: {exposure.topology_status.replaceAll('_', ' ')}</p>
          {exposure.items.length === 0 && <p>No exposure path returned. Absence of a path does not guarantee safety.</p>}
          {exposure.items.map(item => <div key={item.finding_id}><p>{item.affected_service_name} · {item.exposure_status.replaceAll('_', ' ')}</p>{item.paths.map(itemPath => <p key={itemPath.id} className="mt-2 break-words font-mono text-[11px]">{itemPath.has_synthetic_edges && <strong className="text-amber-300">Synthetic topology · </strong>}{itemPath.summary_text}</p>)}</div>)}
          {exposure.warnings.map(warning => <p key={warning.code} className="text-amber-200">{warning.message}</p>)}<p className="text-[10px] text-slate-400">{exposure.disclaimer}</p>
        </section>}
        <Link className="block text-sky-300 hover:underline" to={findingId ? `/exposure-paths?finding_id=${encodeURIComponent(findingId)}` : '/exposure-paths'}>Open Exposure Paths</Link>
        {references.length > 0 && <section><h4 className="mb-2 font-semibold text-white">Recorded references</h4><ul className="max-h-32 space-y-1 overflow-auto">{references.map(url => <li key={url}><a href={url} target="_blank" rel="noopener noreferrer" className="break-all text-sky-300 hover:underline">{url}</a></li>)}</ul></section>}
      </>}
    </aside>
  )
}
