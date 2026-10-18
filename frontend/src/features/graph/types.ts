export interface ExplorerNode {
  id: string
  node_type: 'project' | 'service' | 'package' | 'advisory'
  label: string
  properties: Record<string, unknown>
  classification: 'direct' | 'transitive' | null
  depth: number | null
  advisory_count: number
  severity: string | null
}

export interface ExplorerEdge {
  id: string
  source: string
  target: string
  relationship_type: 'HAS_SERVICE' | 'DEPENDS_ON' | 'AFFECTS'
  properties: Record<string, unknown>
}

export interface ExplorerGraph {
  project_id: string
  nodes: ExplorerNode[]
  edges: ExplorerEdge[]
  root_id: string
  total_packages: number
  total_advisories: number
  counts_complete: boolean
  has_more: boolean
  next_offset: number | null
  warnings: string[]
}

export interface GraphRequest {
  node_id?: string
  q?: string
  offset?: number
  limit?: number
}

export interface GraphFilters {
  classification: 'all' | 'direct' | 'transitive'
  status: 'all' | 'affected' | 'clean'
  severity: string
  mode: 'combined' | 'dependencies' | 'vulnerabilities'
}

export const defaultFilters: GraphFilters = {
  classification: 'all', status: 'all', severity: 'all', mode: 'combined',
}
