import type { ExplorerEdge, ExplorerGraph, ExplorerNode, GraphFilters } from './types'

export const MAX_CANVAS_NODES = 300

export function mergeGraph(previous: ExplorerGraph | null, next: ExplorerGraph): ExplorerGraph {
  if (!previous || previous.project_id !== next.project_id) return next
  const nodes = new Map(previous.nodes.map(node => [node.id, node]))
  next.nodes.forEach(node => nodes.set(node.id, node))
  if (nodes.size > MAX_CANVAS_NODES) {
    return { ...next, warnings: [...next.warnings, 'Canvas limit reached. Showing the latest neighborhood; reset to return to the root.'] }
  }
  const edges = new Map(previous.edges.map(edge => [edge.id, edge]))
  next.edges.forEach(edge => edges.set(edge.id, edge))
  return { ...next, nodes: [...nodes.values()], edges: [...edges.values()], warnings: [...new Set([...previous.warnings, ...next.warnings])] }
}

export function rootPaths(graph: ExplorerGraph): Map<string, ExplorerEdge[]> {
  const adjacency = new Map<string, ExplorerEdge[]>()
  for (const edge of graph.edges) {
    if (edge.relationship_type === 'AFFECTS') continue
    const list = adjacency.get(edge.source) ?? []
    list.push(edge)
    adjacency.set(edge.source, list)
  }
  const byId = new Map(graph.nodes.map(node => [node.id, node]))
  const paths = new Map<string, ExplorerEdge[]>([[graph.root_id, []]])
  const queue = [{ id: graph.root_id, service: '', path: [] as ExplorerEdge[] }]
  const visited = new Set<string>()
  for (let i = 0; i < queue.length; i++) {
    const state = queue[i]
    for (const edge of adjacency.get(state.id) ?? []) {
      const target = byId.get(edge.target)
      if (!target) continue
      const service = target.node_type === 'service' ? String(target.properties.id) : state.service
      const scopes = edge.properties.service_ids
      if (Array.isArray(scopes) && !scopes.includes(service)) continue
      const key = JSON.stringify([service, edge.target])
      if (visited.has(key)) continue
      visited.add(key)
      const path = [...state.path, edge]
      if (!paths.has(edge.target)) paths.set(edge.target, path)
      queue.push({ id: edge.target, service, path })
    }
  }
  return paths
}

export function selectionPath(graph: ExplorerGraph, selectedId: string): ExplorerEdge[] {
  const paths = rootPaths(graph)
  if (paths.has(selectedId)) return paths.get(selectedId)!
  const affects = graph.edges.filter(edge => edge.source === selectedId && edge.relationship_type === 'AFFECTS' && paths.has(edge.target))
  affects.sort((a, b) => paths.get(a.target)!.length - paths.get(b.target)!.length || a.id.localeCompare(b.id))
  return affects.length ? [...paths.get(affects[0].target)!, affects[0]] : []
}

export function filterGraph(graph: ExplorerGraph, filters: GraphFilters) {
  const paths = rootPaths(graph)
  const matching = new Set<string>()
  const severityMatches = new Set(graph.nodes.filter(node =>
    node.node_type === 'advisory' && (filters.severity === 'all' || (node.severity ?? 'unknown').toLowerCase() === filters.severity),
  ).map(node => node.id))
  const affected = new Set(graph.edges.filter(edge => edge.relationship_type === 'AFFECTS' && severityMatches.has(edge.source)).map(edge => edge.target))
  for (const node of graph.nodes) {
    if (node.node_type !== 'package') continue
    if (filters.classification !== 'all' && node.classification !== filters.classification) continue
    if (filters.status === 'affected' && node.advisory_count === 0) continue
    if (filters.status === 'clean' && node.advisory_count > 0) continue
    if (filters.severity !== 'all' && !affected.has(node.id)) continue
    if (filters.mode === 'vulnerabilities' && node.advisory_count === 0) continue
    matching.add(node.id)
  }
  const visible = new Set(matching)
  for (const id of matching) {
    for (const edge of paths.get(id) ?? []) { visible.add(edge.source); visible.add(edge.target) }
  }
  if (filters.mode !== 'dependencies') {
    graph.edges.forEach(edge => {
      if (edge.relationship_type === 'AFFECTS' && matching.has(edge.target) && severityMatches.has(edge.source)) visible.add(edge.source)
    })
  }
  // Empty imports still show actual project/service anchors, never invented dependencies.
  if (!graph.nodes.some(node => node.node_type === 'package')) {
    graph.nodes.filter(node => node.node_type === 'project' || node.node_type === 'service').forEach(node => visible.add(node.id))
  }
  return {
    nodes: graph.nodes.filter(node => visible.has(node.id)),
    edges: graph.edges.filter(edge => visible.has(edge.source) && visible.has(edge.target)),
    context: new Set([...visible].filter(id => byType(graph.nodes, id) === 'package' && !matching.has(id))),
    matchCount: matching.size,
  }
}

function byType(nodes: ExplorerNode[], id: string) {
  return nodes.find(node => node.id === id)?.node_type
}

export function layeredPositions(nodes: ExplorerNode[], edges: ExplorerEdge[]): Map<string, { x: number; y: number }> {
  const layers = new Map<string, number>()
  nodes.forEach(node => layers.set(node.id,
    node.node_type === 'project' ? 0 : node.node_type === 'service' ? 1 : node.depth ?? 2,
  ))
  nodes.filter(node => node.node_type === 'advisory').forEach(node => {
    const targets = edges.filter(edge => edge.source === node.id && edge.relationship_type === 'AFFECTS')
    layers.set(node.id, Math.max(2, ...targets.map(edge => layers.get(edge.target) ?? 2)) + 1)
  })
  const columns = new Map<number, ExplorerNode[]>()
  nodes.forEach(node => {
    const layer = layers.get(node.id)!
    const column = columns.get(layer) ?? []
    column.push(node)
    columns.set(layer, column)
  })
  const positions = new Map<string, { x: number; y: number }>()
  const incoming = new Map<string, string[]>()
  edges.forEach(edge => {
    const target = edge.relationship_type === 'AFFECTS' ? edge.source : edge.target
    const source = edge.relationship_type === 'AFFECTS' ? edge.target : edge.source
    incoming.set(target, [...(incoming.get(target) ?? []), source])
  })
  for (const [level, column] of [...columns].sort(([a], [b]) => a - b)) {
    const center = (id: string) => {
      const parents = (incoming.get(id) ?? []).map(parent => positions.get(parent)?.y).filter((y): y is number => y !== undefined)
      return parents.length ? parents.reduce((a, b) => a + b, 0) / parents.length : 0
    }
    column.sort((a, b) => center(a.id) - center(b.id) || a.label.localeCompare(b.label) || a.id.localeCompare(b.id))
    column.forEach((node, index) => positions.set(node.id, { x: level * 310, y: (index - (column.length - 1) / 2) * 125 }))
  }
  return positions
}

export function severityColor(severity: string | null): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return '#fb7185'
    case 'high': return '#fb923c'
    case 'medium': case 'moderate': return '#facc15'
    case 'low': return '#a78bfa'
    default: return '#94a3b8'
  }
}

export function propertyText(value: unknown): string {
  if (value === undefined || value === null || value === '') return 'Not recorded'
  return typeof value === 'object' ? JSON.stringify(value) : String(value)
}
