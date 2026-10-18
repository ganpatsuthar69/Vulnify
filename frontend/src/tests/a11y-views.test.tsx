import React from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router'
import axe from 'axe-core'

import { AuthProvider } from '@/features/auth/AuthProvider'
import { ProjectProvider } from '@/features/projects/ProjectProvider'

import { DashboardPage } from '@/features/dashboard/DashboardPage'
import { FindingsPage } from '@/features/findings/FindingsPage'
import { FindingDetailPage } from '@/features/findings/FindingDetailPage'
import { DependenciesPage } from '@/features/dependencies/DependenciesPage'
import { ExposurePathsPage } from '@/features/exposure/ExposurePathsPage'
import { RiskPrioritiesPage } from '@/features/priorities/RiskPrioritiesPage'
import { ReviewQueuePage } from '@/features/review/ReviewQueuePage'
import { UpgradeCandidatesPage } from '@/features/remediation/UpgradeCandidatesPage'
import { FixSimulationPage } from '@/features/remediation/FixSimulationPage'
import { GitHubIssuesPage } from '@/features/remediation/GitHubIssuesPage'
import { AiInvestigationPage } from '@/features/intelligence/AiInvestigationPage'
import { InvestigationHistoryPage } from '@/features/intelligence/InvestigationHistoryPage'
import { BenchmarksPage } from '@/features/intelligence/BenchmarksPage'
import { ProjectSettingsPage } from '@/features/projects/ProjectSettingsPage'
import { TraceDrawer } from '@/features/intelligence/TraceDrawer'
import { LockfileImportCard } from '@/features/dependencies/LockfileImportCard'

export async function assertNoA11yViolations(container: HTMLElement, runOptions?: axe.RunOptions) {
  const results = await axe.run(container, {
    runOnly: {
      type: 'tag',
      values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'],
    },
    ...runOptions,
  })

  if (results.violations.length > 0) {
    const details = results.violations
      .map((v) => {
        const nodes = v.nodes.map((n) => `    Target: ${n.target.join(' ')} | HTML: ${n.html}`).join('\n')
        return `[${v.impact?.toUpperCase()}] Rule: ${v.id} - ${v.help}\n${nodes}`
      })
      .join('\n\n')
    throw new Error(`Accessibility Violations Found (${results.violations.length}):\n${details}`)
  }

  expect(results.violations).toEqual([])
}

const mockUser = {
  id: 'usr-1',
  email: 'admin@vulnify.local',
  name: 'Security Admin',
  role: 'admin',
}

const mockProject = {
  id: 'proj-1',
  name: 'E-Commerce Platform',
  ecosystem: 'npm',
  description: 'Production core microservices',
  created_at: 1700000000,
  services: [
    { id: 'svc-1', name: 'api-gateway', internet_facing: true },
    { id: 'svc-2', name: 'payment-processor', internet_facing: false },
  ],
}

function renderWithProviders(ui: React.ReactElement, initialPath: string = '/') {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <AuthProvider>
        <ProjectProvider>
          <main id="main-content">{ui}</main>
        </ProjectProvider>
      </AuthProvider>
    </MemoryRouter>
  )
}

describe('Application Views Automated Accessibility Scans (US-902)', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/api/auth/me')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ user: mockUser }),
        }
      }
      if (url.includes('/api/projects/proj-1/findings/summary')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            advisory_matches: 12,
            findings_with_path: 8,
            findings_without_path: 4,
            findings_needing_decision: 5,
            by_priority: { P1: 2, P2: 4, P3: 2, P4: 4 },
          }),
        }
      }
      if (url.includes('/api/projects/proj-1/findings')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            findings: [
              {
                id: 'find-1',
                advisory_id: 'OSV-2024-001',
                package_name: 'jsonwebtoken',
                package_version: '8.5.1',
                service_name: 'api-gateway',
                severity: 'HIGH',
                priority: 'P1',
                has_path: true,
                shortest_path_depth: 1,
                triage_decision: null,
              },
            ],
            total: 1,
          }),
        }
      }
      if (url.endsWith('/api/projects') || url.endsWith('/api/projects/')) {
        return {
          ok: true,
          status: 200,
          json: async () => [mockProject],
        }
      }
      if (url.includes('/api/benchmarks/results/latest')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            run_id: 'run-latest',
            dataset_version: '1.0.0',
            corpus_id: 'corpus-v1',
            started_at: '2026-10-18T10:00:00Z',
            completed_at: '2026-10-18T10:02:00Z',
            protocol: {
              protocol_version: '1.0.0',
              graph_system_name: 'vulnify-graph-agent',
              rag_system_name: 'text-rag-baseline',
              shared_model: 'gpt-4o',
              shared_provider: 'openai',
              top_k_chunks: 5,
            },
            summary: {
              total_cases: 2,
              graph_success_count: 2,
              rag_success_count: 1,
              graph_error_count: 0,
              rag_error_count: 1,
              graph_avg_duration_ms: 12.0,
              rag_avg_duration_ms: 150.0,
              by_category: {
                path_exists: {
                  total_cases: 2,
                  graph_success_count: 2,
                  rag_success_count: 1,
                  graph_avg_duration_ms: 12.0,
                  rag_avg_duration_ms: 150.0,
                },
              },
            },
            cases: [],
          }),
        }
      }
      if (url.includes('/api/benchmarks/results')) {
        return {
          ok: true,
          status: 200,
          json: async () => [],
        }
      }
      return { ok: true, status: 200, json: async () => ({}) }
    })
  })

  it('scans DashboardPage without violations', async () => {
    const { container } = renderWithProviders(<DashboardPage />)
    await assertNoA11yViolations(container)
  })

  it('scans FindingsPage without violations', async () => {
    const { container } = renderWithProviders(<FindingsPage />, '/findings')
    await assertNoA11yViolations(container)
  })

  it('scans FindingDetailPage without violations', async () => {
    const { container } = render(
      <MemoryRouter initialEntries={['/findings/find-1']}>
        <AuthProvider>
          <ProjectProvider>
            <Routes>
              <Route path="/findings/:id" element={<main><FindingDetailPage /></main>} />
            </Routes>
          </ProjectProvider>
        </AuthProvider>
      </MemoryRouter>
    )
    await assertNoA11yViolations(container)
  })

  it('scans DependenciesPage without violations', async () => {
    const { container } = renderWithProviders(<DependenciesPage />, '/dependencies')
    await assertNoA11yViolations(container)
  })

  it('scans LockfileImportCard without violations', async () => {
    const { container } = renderWithProviders(
      <LockfileImportCard project={mockProject} />
    )
    await assertNoA11yViolations(container)
  })

  it('scans ExposurePathsPage without violations', async () => {
    const { container } = renderWithProviders(<ExposurePathsPage />, '/exposure-paths')
    await assertNoA11yViolations(container)
  })

  it('scans RiskPrioritiesPage without violations', async () => {
    const { container } = renderWithProviders(<RiskPrioritiesPage />, '/priorities')
    await assertNoA11yViolations(container)
  })

  it('scans ReviewQueuePage without violations', async () => {
    const { container } = renderWithProviders(<ReviewQueuePage />, '/review-queue')
    await assertNoA11yViolations(container)
  })

  it('scans UpgradeCandidatesPage without violations', async () => {
    const { container } = renderWithProviders(<UpgradeCandidatesPage />, '/upgrades')
    await assertNoA11yViolations(container)
  })

  it('scans FixSimulationPage without violations', async () => {
    const { container } = renderWithProviders(<FixSimulationPage />, '/simulation')
    await assertNoA11yViolations(container)
  })

  it('scans GitHubIssuesPage without violations', async () => {
    const { container } = renderWithProviders(<GitHubIssuesPage />, '/github-issues')
    await assertNoA11yViolations(container)
  })

  it('scans AiInvestigationPage without violations', async () => {
    const { container } = renderWithProviders(<AiInvestigationPage />, '/investigation')
    await assertNoA11yViolations(container)
  })

  it('scans InvestigationHistoryPage without violations', async () => {
    const { container } = renderWithProviders(<InvestigationHistoryPage />, '/investigation-history')
    await assertNoA11yViolations(container)
  })

  it('scans BenchmarksPage without violations', async () => {
    const { container } = renderWithProviders(<BenchmarksPage />, '/benchmarks')
    await assertNoA11yViolations(container)
  })


  it('scans ProjectSettingsPage without violations', async () => {
    const { container } = renderWithProviders(<ProjectSettingsPage />, '/project-settings')
    await assertNoA11yViolations(container)
  })

  it('scans TraceDrawer open state without violations', async () => {
    const { container } = renderWithProviders(
      <TraceDrawer
        runId="run-1"
        isOpen={true}
        onClose={() => {}}
      />
    )
    await assertNoA11yViolations(container)
  })
})
