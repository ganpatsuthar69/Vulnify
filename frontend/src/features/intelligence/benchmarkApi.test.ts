/**
 * In-browser and compile-time test suite for Benchmark Result Selectors (US-803).
 *
 * Verifies category count derivation, latency aggregation, display mapping,
 * and edge-case resilience without external test dependencies.
 */

import {
  type CaseComparisonResult,
  deriveCategoryMetrics,
  getCategoryDisplayName,
  getSystemDisplayName,
} from './benchmarkApi'

export function runBenchmarkApiTests(): boolean {
  // 1. Category display mappings
  if (getCategoryDisplayName('path_exists') !== 'Path Existence') {
    throw new Error('getCategoryDisplayName path_exists failed')
  }
  if (getCategoryDisplayName('no_path') !== 'No-Path Negative') {
    throw new Error('getCategoryDisplayName no_path failed')
  }
  if (getCategoryDisplayName('exposure') !== 'Architectural Exposure') {
    throw new Error('getCategoryDisplayName exposure failed')
  }
  if (getCategoryDisplayName('ranking') !== 'Deterministic Ranking') {
    throw new Error('getCategoryDisplayName ranking failed')
  }
  if (getCategoryDisplayName('remediation') !== 'Remediation Guidance') {
    throw new Error('getCategoryDisplayName remediation failed')
  }
  if (getCategoryDisplayName('custom_test') !== 'custom_test') {
    throw new Error('getCategoryDisplayName custom_test fallback failed')
  }

  // 2. System display mappings
  if (getSystemDisplayName('graph_agent') !== 'Vulnify Graph Agent') {
    throw new Error('getSystemDisplayName graph_agent failed')
  }
  if (getSystemDisplayName('vulnify-graph-agent') !== 'Vulnify Graph Agent') {
    throw new Error('getSystemDisplayName vulnify-graph-agent failed')
  }
  if (getSystemDisplayName('rag_baseline') !== 'RAG Baseline') {
    throw new Error('getSystemDisplayName rag_baseline failed')
  }
  if (getSystemDisplayName('text-rag-baseline') !== 'RAG Baseline') {
    throw new Error('getSystemDisplayName text-rag-baseline failed')
  }
  if (getSystemDisplayName('unknown_sys') !== 'unknown_sys') {
    throw new Error('getSystemDisplayName unknown_sys fallback failed')
  }

  // 3. Empty cases array handling
  const emptyMetrics = deriveCategoryMetrics([])
  if (emptyMetrics.length !== 0) {
    throw new Error('deriveCategoryMetrics empty cases failed')
  }

  // 4. Metric derivation calculation
  const mockCases: CaseComparisonResult[] = [
    {
      case_id: 'BM-001',
      category: 'path_exists',
      difficulty: 'easy',
      question: 'Does authentication-service reach jsonwebtoken?',
      expected_conclusion: 'Yes, direct path.',
      graph_result: {
        system_id: 'graph_agent',
        status: 'success',
        answer: 'Direct dependency at depth 1.',
        evidence_references: ['cypher:get_project_finding_paths'],
        retrieval_metadata: { depth: 1 },
        duration_ms: 10.0,
      },
      rag_result: {
        system_id: 'rag_baseline',
        status: 'success',
        answer: 'Listed in package.json.',
        evidence_references: ['chunk-1'],
        retrieval_metadata: {},
        duration_ms: 100.0,
      },
    },
    {
      case_id: 'BM-002',
      category: 'path_exists',
      difficulty: 'medium',
      question: 'Shortest path to find-my-way?',
      expected_conclusion: 'Depth 2 via fastify.',
      graph_result: {
        system_id: 'graph_agent',
        status: 'success',
        answer: 'Depth 2 transitive path.',
        evidence_references: ['cypher:get_project_finding_paths'],
        retrieval_metadata: { depth: 2 },
        duration_ms: 20.0,
      },
      rag_result: {
        system_id: 'rag_baseline',
        status: 'failed',
        answer: 'Cannot verify transitive path.',
        evidence_references: [],
        retrieval_metadata: {},
        duration_ms: 200.0,
      },
    },
    {
      case_id: 'BM-005',
      category: 'no_path',
      difficulty: 'easy',
      question: 'Can payment-processor reach pyyaml?',
      expected_conclusion: 'No path found.',
      graph_result: {
        system_id: 'graph_agent',
        status: 'success',
        answer: '0 paths found.',
        evidence_references: ['cypher:get_project_finding_paths'],
        retrieval_metadata: { path_count: 0 },
        duration_ms: 6.0,
      },
      rag_result: {
        system_id: 'rag_baseline',
        status: 'success',
        answer: 'Both in repo.',
        evidence_references: ['chunk-3'],
        retrieval_metadata: {},
        duration_ms: 80.0,
      },
    },
  ]

  const metrics = deriveCategoryMetrics(mockCases)
  if (metrics.length !== 2) {
    throw new Error(`Expected 2 category metric groups, got ${metrics.length}`)
  }

  const pathExists = metrics.find((m) => m.categoryKey === 'path_exists')
  if (!pathExists) {
    throw new Error('Missing path_exists metrics')
  }
  if (pathExists.totalCases !== 2) {
    throw new Error(`Expected 2 total cases for path_exists, got ${pathExists.totalCases}`)
  }
  if (pathExists.graphSuccess !== 2 || pathExists.graphFailed !== 0) {
    throw new Error('Graph execution counts incorrect for path_exists')
  }
  if (pathExists.ragSuccess !== 1 || pathExists.ragFailed !== 1) {
    throw new Error('RAG execution counts incorrect for path_exists')
  }
  if (pathExists.graphAvgDurationMs !== 15.0 || pathExists.ragAvgDurationMs !== 150.0) {
    throw new Error('Duration averages incorrect for path_exists')
  }

  const noPath = metrics.find((m) => m.categoryKey === 'no_path')
  if (!noPath) {
    throw new Error('Missing no_path metrics')
  }
  if (noPath.totalCases !== 1) {
    throw new Error(`Expected 1 total case for no_path, got ${noPath.totalCases}`)
  }
  if (noPath.graphSuccess !== 1 || noPath.ragSuccess !== 1) {
    throw new Error('Execution counts incorrect for no_path')
  }

  return true
}

import { describe, expect, it } from 'vitest'

describe('benchmarkApi', () => {
  it('validates benchmark API mappings and metrics derivation', () => {
    expect(runBenchmarkApiTests()).toBe(true)
  })
})
