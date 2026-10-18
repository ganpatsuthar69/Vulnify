import { memo } from 'react'
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react'
import { Layers, Package, Server, ShieldAlert } from 'lucide-react'
import type { ExplorerNode } from './types'
import { severityColor } from './graphLayout'

export type CanvasNode = Node<{ entity: ExplorerNode; context: boolean; highlighted: boolean }, 'entity'>

export const ExplorerNodeView = memo(function ExplorerNodeView({ data, selected }: NodeProps<CanvasNode>) {
  const node = data.entity
  const advisory = node.node_type === 'advisory'
  const anchor = node.node_type === 'project' || node.node_type === 'service'
  const color = selected ? '#38bdf8' : anchor ? '#38bdf8' : node.advisory_count > 0 || advisory ? severityColor(node.severity) : '#64748b'
  const Icon = advisory ? ShieldAlert : node.node_type === 'project' ? Layers : node.node_type === 'service' ? Server : Package
  const status = advisory ? node.severity ?? 'Unknown severity' : anchor ? node.node_type : node.advisory_count > 0 ? `${node.advisory_count} advisories · ${node.severity ?? 'unknown'}` : 'No verified advisories'
  return (
    <div
      title={`${node.label}\n${node.classification ?? node.node_type} · ${status}\nClick to inspect; drag to reposition`}
      className="w-[225px] rounded-xl border bg-[#101b29] px-3 py-3 shadow-lg"
      style={{ borderColor: color, boxShadow: selected ? `0 0 0 2px ${color}` : data.highlighted ? `0 0 0 1px ${color}` : undefined, opacity: data.context ? 0.55 : 1 }}
    >
      {!advisory && <Handle type="target" position={Position.Left} className="!h-2 !w-2 !bg-slate-400" />}
      <div className="mb-2 flex items-center justify-between gap-2 text-[10px] uppercase tracking-wider text-slate-300">
        <span className="flex items-center gap-1.5"><Icon size={13} style={{ color }} />{node.classification ?? node.node_type}</span>
        {data.context && <span>Context</span>}
      </div>
      <div className="truncate font-mono text-xs font-semibold text-white">{String(node.properties.name ?? node.label)}</div>
      {node.node_type === 'package' && <div className="mt-1 font-mono text-[11px] text-slate-300">{String(node.properties.version ?? 'Version not recorded')}</div>}
      <div className="mt-2 truncate text-[10px]" style={{ color: anchor ? '#7dd3fc' : node.advisory_count > 0 || advisory ? severityColor(node.severity) : '#cbd5e1' }}>{status}</div>
      <Handle type="source" position={advisory ? Position.Left : Position.Right} className="!h-2 !w-2 !bg-slate-400" />
    </div>
  )
})
