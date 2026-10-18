import { useState, useEffect, useMemo, useCallback } from 'react'
import {
  ReactFlow,
  Controls,
  Background,
  MarkerType,
  Handle,
  Position,
  type Node,
  type Edge,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import {
  Layers,
  Package,
  ShieldAlert,
  AlertTriangle,
  Info,
  Loader2,
  RefreshCw,
  FileCode,
  Hash,
  Clock,
} from 'lucide-react'
import { getFindingDependencyPaths, ProjectApiError } from '@/features/projects/projectApi'
import type { FindingPathsResponse, DependencyPath, PathNode } from '@/features/projects/types'
import { DataQualityBanner } from '@/shared/components/DataQualityBanner'

// Node data shape for React Flow custom node
interface DependencyNodeData extends Record<string, unknown> {
  node: PathNode
  isSelected: boolean
}

// Custom Node Component for high-contrast, accessible presentation
function DependencyNodeView({ data }: NodeProps) {
  const nodeData = data as unknown as DependencyNodeData
  const n = nodeData.node
  const isSelected = nodeData.isSelected

  const isService = n.is_entry_point || n.node_type === 'service'
  const isTarget = n.is_target

  const borderColor = isSelected
    ? 'ring-2 ring-sky-400 border-sky-400'
    : isTarget
    ? 'border-rose-500/80 bg-[#160d12]'
    : isService
    ? 'border-sky-500/80 bg-[#0c1624]'
    : 'border-slate-700 bg-[#0f1722]'

  const badgeColor = isTarget
    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
    : isService
    ? 'bg-sky-500/20 text-sky-300 border-sky-500/40'
    : 'bg-slate-800 text-slate-300 border-slate-700'

  return (
    <div
      tabIndex={0}
      role="button"
      aria-label={`${n.display_name} (${isTarget ? 'Vulnerable package version' : isService ? 'Service entry point' : 'Intermediate dependency'})`}
      className={`rounded-xl border p-3.5 shadow-lg transition-all min-w-[210px] max-w-[240px] text-left outline-none ${borderColor}`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!bg-slate-400 !w-2.5 !h-2.5 !-left-1.5"
      />

      <div className="flex items-center justify-between gap-2 mb-2">
        <span
          className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border ${badgeColor}`}
        >
          {isService ? (
            <>
              <Layers className="h-3 w-3 shrink-0" aria-hidden="true" />
              <span>Service</span>
            </>
          ) : isTarget ? (
            <>
              <ShieldAlert className="h-3 w-3 shrink-0" aria-hidden="true" />
              <span>Vulnerable</span>
            </>
          ) : (
            <>
              <Package className="h-3 w-3 shrink-0" aria-hidden="true" />
              <span>Transitive</span>
            </>
          )}
        </span>
        {n.ecosystem && (
          <span className="text-[10px] uppercase font-mono text-slate-400">{n.ecosystem}</span>
        )}
      </div>

      <div className="font-mono text-xs font-bold text-white truncate" title={n.display_name}>
        {n.package_name ?? n.display_name}
      </div>

      {n.package_version && (
        <div className="font-mono text-[11px] text-sky-300 mt-0.5 font-medium truncate">
          v{n.package_version}
        </div>
      )}

      <Handle
        type="source"
        position={Position.Right}
        className="!bg-slate-400 !w-2.5 !h-2.5 !-right-1.5"
      />
    </div>
  )
}

const nodeTypes = {
  dependencyNode: DependencyNodeView,
}

interface DependencyPathVisualizerProps {
  projectId: string
  findingId: string
  className?: string
}

export function DependencyPathVisualizer({
  projectId,
  findingId,
  className = '',
}: DependencyPathVisualizerProps) {
  const [data, setData] = useState<FindingPathsResponse | null>(null)
  const [selectedPathIndex, setSelectedPathIndex] = useState(0)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [reloadTrigger, setReloadTrigger] = useState(0)

  const loadPaths = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const response = await getFindingDependencyPaths(projectId, findingId, {
        max_depth: 8,
        limit: 5,
      })
      setData(response)
      if (response.paths.length > 0) {
        setSelectedPathIndex(0)
        // Default selected node to the vulnerable target node
        const firstPath = response.paths[0]
        const target = firstPath.nodes.find((n) => n.is_target) || firstPath.nodes[firstPath.nodes.length - 1]
        setSelectedNodeId(target.id)
      } else {
        setSelectedNodeId(null)
      }
    } catch (err) {
      if (err instanceof ProjectApiError) {
        setError(err.message)
      } else {
        setError('Failed to fetch dependency paths.')
      }
    } finally {
      setIsLoading(false)
    }
  }, [projectId, findingId])

  useEffect(() => {
    void loadPaths()
  }, [loadPaths, reloadTrigger])

  const activePath: DependencyPath | null = useMemo(() => {
    if (!data || data.paths.length === 0) return null
    return data.paths[selectedPathIndex] ?? data.paths[0]
  }, [data, selectedPathIndex])

  // Convert activePath nodes to React Flow Node structures
  const rfNodes: Node[] = useMemo(() => {
    if (!activePath) return []
    const spacingX = 280
    const startY = 80

    return activePath.nodes.map((n, idx) => ({
      id: n.id,
      type: 'dependencyNode',
      position: { x: 30 + idx * spacingX, y: startY },
      data: {
        node: n,
        isSelected: selectedNodeId === n.id,
      },
    }))
  }, [activePath, selectedNodeId])

  // Convert activePath edges to React Flow Edge structures
  const rfEdges: Edge[] = useMemo(() => {
    if (!activePath) return []
    return activePath.edges.map((e) => ({
      id: e.id,
      source: e.source_id,
      target: e.target_id,
      animated: true,
      label: e.direct ? 'direct' : 'transitive',
      labelStyle: { fill: '#94a3b8', fontSize: 10, fontFamily: 'monospace' },
      labelBgStyle: { fill: '#0b121a', fillOpacity: 0.8 },
      style: {
        stroke: e.direct ? '#38bdf8' : '#64748b',
        strokeWidth: 2,
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: e.direct ? '#38bdf8' : '#64748b',
        width: 14,
        height: 14,
      },
    }))
  }, [activePath])

  const selectedNode: PathNode | null = useMemo(() => {
    if (!activePath || !selectedNodeId) return null
    return activePath.nodes.find((n) => n.id === selectedNodeId) ?? null
  }, [activePath, selectedNodeId])

  // 1. Loading State
  if (isLoading) {
    return (
      <div
        className={`rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-center text-slate-400 ${className}`}
        role="status"
        aria-live="polite"
      >
        <Loader2 className="mx-auto h-8 w-8 animate-spin text-sky-400" aria-hidden="true" />
        <span className="mt-3 block text-xs font-medium text-slate-300">
          Computing shortest dependency paths in FalkorDB...
        </span>
      </div>
    )
  }

  // 2. Error State
  if (error) {
    return (
      <div
        className={`rounded-xl border border-rose-900/50 bg-[#160c11] p-8 text-center text-xs text-rose-300 ${className}`}
        role="alert"
      >
        <AlertTriangle className="mx-auto h-8 w-8 text-rose-400 mb-2" aria-hidden="true" />
        <h3 className="font-bold text-white text-sm">Failed to Load Dependency Paths</h3>
        <p className="mt-1 text-slate-300">{error}</p>
        <button
          type="button"
          onClick={() => setReloadTrigger((prev) => prev + 1)}
          className="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition-colors"
        >
          <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
          <span>Retry</span>
        </button>
      </div>
    )
  }

  // 3. No Path Found State (AC-1 & Honesty Requirement)
  if (!data || !data.has_path || data.paths.length === 0) {
    return (
      <div className={`space-y-4 ${className}`}>
        {/* Safety Disclaimer Banner */}
        <div
          role="alert"
          className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-200 leading-relaxed"
        >
          <div className="flex items-center gap-2 font-bold text-amber-300 mb-1">
            <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>No Path Found — Absence of Path Does Not Guarantee Safety</span>
          </div>
          <p>
            {data?.no_path_message || (
              `No architectural dependency path was found from service "${data?.service_name ?? 'service'}" to package "${data?.package_name ?? 'package'}" within the maximum traversal depth of ${data?.max_depth_applied ?? 8} hops. 'No path found' does not guarantee safety: the target package version is present in the project's dependency manifest and may still be reached via dynamically resolved dependencies, undeclared calls, or out-of-scope services.`
            )}
          </p>
        </div>

        {data?.warnings && data.warnings.length > 0 && (
          <DataQualityBanner warnings={data.warnings} />
        )}

        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-10 text-center text-xs text-slate-400">
          <Info className="mx-auto h-8 w-8 text-slate-500 mb-2" aria-hidden="true" />
          <h3 className="text-sm font-semibold text-white">No Reachable Dependency Path</h3>
          <p className="mt-1 text-slate-400 max-w-md mx-auto">
            The target package version is not reachable from the service entry point within the bounded search depth of {data?.max_depth_applied ?? 8} hops in the current FalkorDB graph.
          </p>
        </div>
      </div>
    )
  }

  // 4. Populated State (AC-1, AC-2, AC-3)
  return (
    <div className={`space-y-4 ${className}`}>
      {/* Traversal Bound & Truncation Notice */}
      {data.is_truncated && (
        <div className="rounded-lg border border-sky-500/30 bg-sky-500/10 px-4 py-2.5 text-xs text-sky-200 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Info className="h-4 w-4 shrink-0 text-sky-400" aria-hidden="true" />
            <span>
              Showing the shortest {data.paths.length} paths (bounded by limit of {data.limit_applied} and depth of {data.max_depth_applied}). Additional paths may exist.
            </span>
          </div>
        </div>
      )}

      {/* Path Selector Bar (when multiple paths are available) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-300">
            Available Paths ({data.paths.length}):
          </span>
          <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Shortest dependency paths">
            {data.paths.map((p, idx) => (
              <button
                key={p.id}
                type="button"
                role="tab"
                aria-selected={selectedPathIndex === idx}
                aria-controls={`path-panel-${idx}`}
                onClick={() => {
                  setSelectedPathIndex(idx)
                  const target = p.nodes.find((n) => n.is_target) || p.nodes[p.nodes.length - 1]
                  setSelectedNodeId(target.id)
                }}
                className={`rounded px-2.5 py-1 text-xs font-mono font-medium transition-colors ${
                  selectedPathIndex === idx
                    ? 'bg-sky-500 text-white font-bold'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                Path {idx + 1} ({p.depth} {p.depth === 1 ? 'hop' : 'hops'} &bull; {p.is_direct ? 'direct' : 'transitive'})
              </button>
            ))}
          </div>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 text-[11px] text-slate-400">
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-sky-400" aria-hidden="true" />
            <span>Service Entry</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-slate-500" aria-hidden="true" />
            <span>Intermediate Package</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-rose-500" aria-hidden="true" />
            <span>Affected Package</span>
          </div>
        </div>
      </div>

      {/* Semantic Screen-Reader Synchronized Text Alternative (AC-3) */}
      <div
        className="rounded-lg border border-slate-800 bg-[#0b121a] px-4 py-3 text-xs"
        aria-live="polite"
      >
        <span className="text-slate-400 font-semibold block mb-1">
          Accessible Path Summary:
        </span>
        <div className="font-mono text-slate-200 select-all">
          {activePath?.summary_text}
        </div>
      </div>

      {/* Interactive Visual Graph Canvas & Provenance Panel */}
      <div className="grid gap-4 lg:grid-cols-3">
        {/* React Flow Canvas (Col 1 & 2) */}
        <div className="lg:col-span-2 h-[380px] rounded-xl border border-slate-800 bg-[#0b121a] relative overflow-hidden">
          <ReactFlow
            nodes={rfNodes}
            edges={rfEdges}
            nodeTypes={nodeTypes}
            onNodeClick={(_evt, node) => setSelectedNodeId(node.id)}
            fitView
            fitViewOptions={{ padding: 0.3 }}
            minZoom={0.2}
            maxZoom={2.0}
            attributionPosition="bottom-right"
          >
            <Background color="#1e293b" gap={16} size={1} />
            <Controls className="!bg-[#0f1822] !border-slate-800 !text-slate-300 [&>button]:!border-slate-800 [&>button]:!fill-slate-300" />
          </ReactFlow>
        </div>

        {/* Node Details & Provenance Panel (Col 3, AC-2) */}
        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-4">
          <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Info className="h-4 w-4 text-sky-400" aria-hidden="true" />
            <span>Selected Node Details</span>
          </h3>

          {selectedNode ? (
            <div className="space-y-3 text-xs">
              <div className="border-b border-slate-800/80 pb-2">
                <span className="text-slate-400 block text-[11px]">Display Name:</span>
                <span className="font-mono font-bold text-white break-all">
                  {selectedNode.display_name}
                </span>
              </div>

              <div className="border-b border-slate-800/80 pb-2">
                <span className="text-slate-400 block text-[11px]">Node Type:</span>
                <span className="font-semibold text-slate-200 capitalize">
                  {selectedNode.node_type} {selectedNode.is_entry_point ? '(Root Entry Point)' : selectedNode.is_target ? '(Vulnerable Target)' : '(Transitive Dependency)'}
                </span>
              </div>

              {selectedNode.purl && (
                <div className="border-b border-slate-800/80 pb-2">
                  <span className="text-slate-400 block text-[11px]">Package URL (PURL):</span>
                  <span className="font-mono text-[11px] text-sky-300 break-all">
                    {selectedNode.purl}
                  </span>
                </div>
              )}

              {/* Provenance Details (AC-2) */}
              <div className="pt-1 space-y-2">
                <span className="text-slate-300 font-bold text-[11px] uppercase tracking-wider block">
                  Provenance Record
                </span>

                <div className="rounded-lg bg-[#0b121a] p-3 border border-slate-800/80 space-y-2 text-[11px]">
                  <div className="flex items-start gap-2 text-slate-300">
                    <FileCode className="h-3.5 w-3.5 text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />
                    <div>
                      <span className="text-slate-400 block text-[10px]">Import Source File:</span>
                      <span className="font-mono text-white">
                        {selectedNode.provenance.source_filename ?? 'Unknown source'}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-start gap-2 text-slate-300">
                    <Hash className="h-3.5 w-3.5 text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />
                    <div>
                      <span className="text-slate-400 block text-[10px]">Content SHA-256 Digest:</span>
                      <span className="font-mono text-[10px] text-slate-300 break-all select-all">
                        {selectedNode.provenance.content_hash ?? 'Hash unavailable'}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-start gap-2 text-slate-300">
                    <Clock className="h-3.5 w-3.5 text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />
                    <div>
                      <span className="text-slate-400 block text-[10px]">Import Timestamp:</span>
                      <span className="font-mono text-slate-300">
                        {selectedNode.provenance.imported_at
                          ? new Date(selectedNode.provenance.imported_at * 1000).toUTCString()
                          : 'Timestamp unavailable'}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-start gap-2 text-slate-300">
                    <span className="text-slate-400 block text-[10px]">Classification:</span>
                    <span className="font-semibold text-slate-200 capitalize">
                      {selectedNode.provenance.classification} ({selectedNode.provenance.origin})
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-slate-400 text-xs italic py-6 text-center">
              Click any node in the graph above to inspect its properties and provenance.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
