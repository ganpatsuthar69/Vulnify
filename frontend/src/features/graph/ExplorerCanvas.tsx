import { useEffect, useMemo, useState } from 'react'
import { ReactFlow, Background, Controls, MiniMap, MarkerType, applyNodeChanges, type Edge, type ReactFlowInstance } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { ExplorerNodeView, type CanvasNode } from './ExplorerNodeView'
import { layeredPositions } from './graphLayout'
import type { ExplorerNode, ExplorerEdge } from './types'

const nodeTypes = { entity: ExplorerNodeView }

interface Props {
  nodes: ExplorerNode[]
  edges: ExplorerEdge[]
  context: Set<string>
  selectedId: string | null
  highlightedEdges: Set<string>
  onSelect: (id: string) => void
  onReady: (instance: ReactFlowInstance<CanvasNode>) => void
}
export function ExplorerCanvas({ nodes, edges, context, selectedId, highlightedEdges, onSelect, onReady }: Props) {
  const positions = useMemo(() => layeredPositions(nodes, edges), [nodes, edges])
  const [positionOverrides, setPositionOverrides] = useState(new Map<string, { x: number; y: number }>())
  const [instance, setInstance] = useState<ReactFlowInstance<CanvasNode> | null>(null)
  const highlightedNodes = useMemo(() => new Set(edges.filter(edge => highlightedEdges.has(edge.id)).flatMap(edge => [edge.source, edge.target])), [edges, highlightedEdges])
  const canvasNodes: CanvasNode[] = useMemo(() => nodes.map(node => ({
    id: node.id, type: 'entity', position: positionOverrides.get(node.id) ?? positions.get(node.id)!,
    data: { entity: node, context: context.has(node.id), highlighted: highlightedNodes.has(node.id) },
    selected: node.id === selectedId,
    ariaLabel: `${node.label}, ${node.classification ?? node.node_type}`,
  })), [nodes, positions, positionOverrides, context, selectedId, highlightedNodes])
  const canvasEdges: Edge[] = useMemo(() => edges.map(edge => {
    const highlighted = highlightedEdges.has(edge.id)
    const color = highlighted ? '#38bdf8' : edge.relationship_type === 'AFFECTS' ? '#fb7185' : '#64748b'
    return {
      id: edge.id, source: edge.source, target: edge.target,
      type: 'smoothstep', label: highlighted || edge.relationship_type === 'AFFECTS' ? edge.relationship_type : undefined,
      style: { stroke: color, strokeWidth: highlighted ? 2.5 : 1.3, opacity: selectedId && !highlighted ? 0.3 : 1 },
      markerEnd: { type: MarkerType.ArrowClosed, color },
      labelStyle: { fill: '#e2e8f0', fontSize: 9 }, labelBgStyle: { fill: '#0b121a', fillOpacity: 0.95 },
      ariaLabel: `${edge.source} ${edge.relationship_type} ${edge.target}`,
    }
  }), [edges, highlightedEdges, selectedId])

  useEffect(() => {
    if (!instance) return
    const frame = requestAnimationFrame(() => { void instance.fitView({ padding: 0.18, maxZoom: 1, duration: 250 }) })
    return () => cancelAnimationFrame(frame)
  }, [instance, positions])

  return (
    <div className="h-[620px] min-w-0 overflow-hidden rounded-xl border border-slate-800 bg-[#0b121a] xl:h-[700px]" role="region" aria-label="Interactive package relationship graph">
      <ReactFlow<CanvasNode>
        nodes={canvasNodes} edges={canvasEdges} nodeTypes={nodeTypes}
        onInit={flow => { setInstance(flow); onReady(flow) }}
        onNodeClick={(_, node) => onSelect(node.id)}
        onNodesChange={changes => {
          const positionsChanged = changes.filter(change => change.type === 'position')
          if (!positionsChanged.length) return
          const moved = applyNodeChanges(positionsChanged, canvasNodes)
          setPositionOverrides(previous => {
            const next = new Map(previous)
            for (const change of positionsChanged) {
              const node = moved.find(item => item.id === change.id)
              if (node) next.set(node.id, node.position)
            }
            return next
          })
        }}
        nodesConnectable={false} edgesReconnectable={false} deleteKeyCode={null}
        minZoom={0.08} maxZoom={2} fitView colorMode="dark" onlyRenderVisibleElements
      >
        <Background color="#26374b" gap={22} size={1} />
        <Controls showInteractive={false} />
        <MiniMap pannable zoomable nodeColor={node => ((node.data as CanvasNode['data']).entity.node_type === 'advisory' ? '#fb7185' : '#38bdf8')} className="!bg-[#101b29]" maskColor="rgba(5,10,18,0.65)" />
      </ReactFlow>
    </div>
  )
}
