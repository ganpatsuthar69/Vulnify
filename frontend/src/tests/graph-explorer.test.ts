import { describe, it, expect } from 'vitest'
import {
  filterGraph,
  layeredPositions,
  mergeGraph,
  rootPaths,
  selectionPath,
  severityColor,
} from '@/features/graph/graphLayout'
import { defaultFilters, type ExplorerEdge, type ExplorerGraph, type ExplorerNode } from '@/features/graph/types'

function node(id: string, type: ExplorerNode['node_type'], extra: Partial<ExplorerNode> = {}): ExplorerNode {
  return {
    id, node_type: type, label: id, properties: { id: id.split(':')[1] },
    classification: null, depth: null, advisory_count: 0, severity: null, ...extra,
  }
}

function edge(source: string, target: string, kind: ExplorerEdge['relationship_type'], properties: Record<string, unknown> = {}): ExplorerEdge {
  return { id: `edge:${source}->${target}:${kind}`, source, target, relationship_type: kind, properties }
}

const service = node('service:proj:api', 'service', { depth: 1, properties: { id: 'proj:api' } })
const direct = node('package:a@1', 'package', { classification: 'direct', depth: 2 })
const transitive = node('package:b@1', 'package', { classification: 'transitive', depth: 3, advisory_count: 1, severity: 'High' })
const advisory = node('advisory:GHSA-1', 'advisory', { severity: 'High' })
const clean = node('package:c@1', 'package', { classification: 'transitive', depth: 3 })

const base: ExplorerGraph = {
  project_id: 'proj', root_id: 'project:proj',
  nodes: [node('project:proj', 'project', { depth: 0 }), service, direct, transitive, advisory, clean],
  edges: [
    edge('project:proj', 'service:proj:api', 'HAS_SERVICE'),
    edge('service:proj:api', 'package:a@1', 'DEPENDS_ON'),
    edge('package:a@1', 'package:b@1', 'DEPENDS_ON', { service_ids: ['proj:api'] }),
    edge('package:a@1', 'package:c@1', 'DEPENDS_ON', { service_ids: ['other:svc'] }),
    edge('advisory:GHSA-1', 'package:b@1', 'AFFECTS', { reason: 'range', finding_ids: ['find-1'] }),
  ],
  total_packages: 3, total_advisories: 1, counts_complete: true, has_more: false, next_offset: null, warnings: [],
}

describe('project graph explorer logic', () => {
  it('root paths follow real edges and service context', () => {
    const paths = rootPaths(base)
    expect(paths.get('package:b@1')?.map(e => e.target)).toEqual(['service:proj:api', 'package:a@1', 'package:b@1'])
    expect(paths.has('package:c@1')).toBe(false)
    expect(selectionPath(base, 'advisory:GHSA-1').map(e => e.id)).toEqual([
      'edge:project:proj->service:proj:api:HAS_SERVICE',
      'edge:service:proj:api->package:a@1:DEPENDS_ON',
      'edge:package:a@1->package:b@1:DEPENDS_ON',
      'edge:advisory:GHSA-1->package:b@1:AFFECTS',
    ])
    expect(selectionPath(base, 'package:c@1')).toEqual([])
  })

  it('terminates on dependency cycles', () => {
    const cyclic: ExplorerGraph = {
      ...base,
      edges: [...base.edges, edge('package:b@1', 'package:a@1', 'DEPENDS_ON', { service_ids: ['proj:api'] })],
    }
    expect(rootPaths(cyclic).get('package:b@1')?.length).toBe(3)
  })

  it('filters by view mode, status, severity, and classification', () => {
    expect(filterGraph(base, defaultFilters).nodes.map(n => n.id)).toContain('package:c@1')
    expect(filterGraph(base, { ...defaultFilters, mode: 'vulnerabilities' }).nodes.map(n => n.id))
      .toEqual(expect.arrayContaining(['advisory:GHSA-1', 'package:b@1']))
    expect(filterGraph(base, { ...defaultFilters, mode: 'vulnerabilities' }).nodes.map(n => n.id))
      .not.toContain('package:c@1')
    expect(filterGraph(base, { ...defaultFilters, mode: 'dependencies' }).nodes.map(n => n.id))
      .not.toContain('advisory:GHSA-1')
    const low = filterGraph(base, { ...defaultFilters, severity: 'low' })
    expect(low.matchCount).toBe(0)
    expect(low.nodes).toEqual([])
    expect(filterGraph(base, { ...defaultFilters, severity: 'high' }).matchCount).toBe(1)
    expect(filterGraph(base, { ...defaultFilters, classification: 'direct' }).matchCount).toBe(1)
    expect(filterGraph(base, { ...defaultFilters, status: 'clean' }).nodes.map(n => n.id)).not.toContain('package:b@1')
  })

  it('empty graph keeps only real anchors and merge deduplicates', () => {
    const empty: ExplorerGraph = {
      ...base, nodes: [base.nodes[0]!], edges: [], total_packages: 0, total_advisories: 0,
    }
    expect(filterGraph(empty, defaultFilters).nodes.map(n => n.id)).toEqual(['project:proj'])
    const merged = mergeGraph(base, base)
    expect(merged.nodes.length).toBe(base.nodes.length)
    expect(merged.edges.length).toBe(base.edges.length)
    expect(mergeGraph(null, base)).toBe(base)
  })

  it('layers deterministically: root, service, depth, advisory column', () => {
    const positions = layeredPositions(base.nodes, base.edges)
    expect(positions.get('project:proj')!.x).toBe(0)
    expect(positions.get('service:proj:api')!.x).toBe(310)
    expect(positions.get('package:a@1')!.x).toBe(620)
    expect(positions.get('package:b@1')!.x).toBe(930)
    expect(positions.get('advisory:GHSA-1')!.x).toBeGreaterThan(positions.get('package:b@1')!.x)
    expect(layeredPositions(base.nodes, base.edges)).toEqual(positions)
  })

  it('maps severities to distinct accessible colors', () => {
    expect(severityColor('critical')).not.toBe(severityColor('high'))
    expect(severityColor('moderate')).toBe(severityColor('medium'))
    expect(severityColor(null)).toBe('#94a3b8')
  })
})
