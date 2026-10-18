import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router'

import { AuthProvider } from '@/features/auth/AuthProvider'
import { ProjectProvider, useProjects } from '@/features/projects/ProjectProvider'
import { AppLayout } from '@/shared/components/AppLayout'
import { FindingsPage } from '@/features/findings/FindingsPage'
import {
  getProjectFindings,
  recordFindingDecision,
} from '@/features/projects/projectApi'
import type { Project } from '@/features/projects/types'

const mockUser = {
  id: 'usr-1',
  email: 'security@vulnify.local',
  name: 'Security Engineer',
  role: 'user',
}

const mockProjects: Project[] = [
  {
    id: 'proj-alpha',
    name: 'Alpha Payments',
    ecosystem: 'npm',
    description: 'Payments service',
    created_at: 1700000000,
  },
  {
    id: 'proj-beta',
    name: 'Beta Auth',
    ecosystem: 'npm',
    description: 'Authentication service',
    created_at: 1700000100,
  },
]

describe('Frontend Multi-Project Data Isolation & Switching', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    localStorage.clear()

    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      // Auth me
      if (url.includes('/api/auth/me')) {
        return {
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({ user: mockUser }),
        }
      }

      // List projects
      if (url.endsWith('/api/projects') || url.includes('/api/projects?')) {
        return {
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => mockProjects,
        }
      }

      // Capabilities
      if (url.includes('/capabilities')) {
        return {
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({ capabilities: [] }),
        }
      }

      // Project Alpha services
      if (url.includes('/api/projects/proj-alpha/services')) {
        return {
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => [{ id: 'svc-alpha', name: 'alpha-service', internet_facing: true }],
        }
      }

      // Project Beta services
      if (url.includes('/api/projects/proj-beta/services')) {
        return {
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => [{ id: 'svc-beta', name: 'beta-service', internet_facing: false }],
        }
      }

      // Project Alpha findings summary
      if (url.includes('/api/projects/proj-alpha/findings/summary')) {
        return {
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({
            advisory_matches: 1,
            findings_with_path: 1,
            findings_without_path: 0,
            findings_needing_decision: 1,
            by_priority: { P1: 1, P2: 0, P3: 0, P4: 0 },
          }),
        }
      }

      // Project Beta findings summary
      if (url.includes('/api/projects/proj-beta/findings/summary')) {
        return {
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({
            advisory_matches: 2,
            findings_with_path: 0,
            findings_without_path: 2,
            findings_needing_decision: 2,
            by_priority: { P1: 0, P2: 2, P3: 0, P4: 0 },
          }),
        }
      }

      // Project Alpha findings
      if (url.includes('/api/projects/proj-alpha/findings')) {
        return {
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({
            items: [
              {
                id: 'finding-alpha-101',
                advisory_id: 'GHSA-alpha-101',
                advisory_summary: 'Alpha Package Vulnerability',
                package_name: 'alpha-pkg',
                package_version: '1.0.0',
                service_id: 'svc-alpha',
                service_name: 'alpha-service',
                severity: 'HIGH',
                priority: 'High',
                status: 'open',
                path_depth: 1,
                path_status: 'path_found',
              },
            ],
            page: 1,
            page_size: 25,
            total: 1,
            total_pages: 1,
          }),
        }
      }

      // Project Beta findings
      if (url.includes('/api/projects/proj-beta/findings')) {
        return {
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({
            items: [
              {
                id: 'finding-beta-202',
                advisory_id: 'GHSA-beta-202',
                advisory_summary: 'Beta Security Flaw',
                package_name: 'beta-pkg',
                package_version: '2.5.0',
                service_id: 'svc-beta',
                service_name: 'beta-service',
                severity: 'CRITICAL',
                priority: 'Highest',
                status: 'open',
                path_depth: 0,
                path_status: 'no_path_found',
              },
            ],
            page: 1,
            page_size: 25,
            total: 1,
            total_pages: 1,
          }),
        }
      }

      // Project data quality
      if (url.includes('/data-quality')) {
        return {
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({ warnings: [] }),
        }
      }

      return {
        ok: false,
        status: 404,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({ error: 'Not found' }),
      }
    })
  })

  it('renders Project Alpha findings initially, and switches to Project Beta findings when project is selected', async () => {
    function SwitcherConsumer() {
      const { selectProject, activeProject } = useProjects()
      return (
        <div>
          <span data-testid="active-project-label">{activeProject?.name}</span>
          <button
            data-testid="switch-to-beta-btn"
            onClick={() => selectProject('proj-beta')}
          >
            Switch to Beta
          </button>
          <button
            data-testid="switch-to-alpha-btn"
            onClick={() => selectProject('proj-alpha')}
          >
            Switch to Alpha
          </button>
        </div>
      )
    }

    render(
      <MemoryRouter initialEntries={['/findings']}>
        <AuthProvider>
          <ProjectProvider>
            <SwitcherConsumer />
            <FindingsPage />
          </ProjectProvider>
        </AuthProvider>
      </MemoryRouter>
    )

    // Wait for Project Alpha to load
    await waitFor(() => {
      const label = screen.getByTestId('active-project-label')
      expect(label.textContent).toBe('Alpha Payments')
    })

    // Verify Alpha records are visible
    await waitFor(() => {
      expect(screen.queryByText('alpha-pkg')).not.toBeNull()
      expect(screen.queryByText('Alpha Package Vulnerability')).not.toBeNull()
    })
    expect(screen.queryByText('beta-pkg')).toBeNull()

    // Switch to Project Beta
    fireEvent.click(screen.getByTestId('switch-to-beta-btn'))

    // Verify Project Beta is now active and its records are displayed
    await waitFor(() => {
      const label = screen.getByTestId('active-project-label')
      expect(label.textContent).toBe('Beta Auth')
    })

    await waitFor(() => {
      expect(screen.queryByText('beta-pkg')).not.toBeNull()
      expect(screen.queryByText('Beta Security Flaw')).not.toBeNull()
    })
    // Alpha records must no longer be present
    expect(screen.queryByText('alpha-pkg')).toBeNull()

    // Switch back to Alpha
    fireEvent.click(screen.getByTestId('switch-to-alpha-btn'))

    await waitFor(() => {
      const label = screen.getByTestId('active-project-label')
      expect(label.textContent).toBe('Alpha Payments')
    })
    await waitFor(() => {
      expect(screen.queryByText('alpha-pkg')).not.toBeNull()
    })
    expect(screen.queryByText('beta-pkg')).toBeNull()
  })

  it('clears URL query parameters on project switch to avoid stale filter contamination', async () => {
    render(
      <MemoryRouter initialEntries={['/findings?service_id=svc-alpha&search=special']}>
        <AuthProvider>
          <ProjectProvider>
            <AppLayout />
          </ProjectProvider>
        </AuthProvider>
      </MemoryRouter>
    )

    // Wait for project selector button to be rendered with active project
    await waitFor(() => {
      const btn = screen.getByRole('button', { name: /Active Project/i })
      expect(btn.textContent).toContain('Alpha Payments')
    })

    // Open project dropdown
    fireEvent.click(screen.getByRole('button', { name: /Active Project/i }))

    // Click Beta Auth in the dropdown
    const betaOption = screen.getByRole('option', { name: /Beta Auth/i })
    fireEvent.click(betaOption)

    // After switching, the active project is Beta Auth
    await waitFor(() => {
      const btn = screen.getByRole('button', { name: /Active Project/i })
      expect(btn.textContent).toContain('Beta Auth')
    })
  })

  it('API client isolates findings and decisions between distinct project IDs', async () => {
    const alphaFindingItem = {
      id: 'alpha-f-1',
      project_id: 'proj-alpha',
      service_id: 'svc-alpha',
      service_name: 'alpha-service',
      advisory_id: 'GHSA-alpha-1',
      package_name: 'alpha-pkg',
      package_version: '1.0.0',
      status: 'open',
    }
    const betaFindingItem = {
      id: 'beta-f-1',
      project_id: 'proj-beta',
      service_id: 'svc-beta',
      service_name: 'beta-service',
      advisory_id: 'GHSA-beta-1',
      package_name: 'beta-pkg',
      package_version: '2.0.0',
      status: 'open',
    }

    let alphaStatus = 'open'
    let alphaJustification: string | null = null

    const fetchMock = vi.fn().mockImplementation(async (url: string, opts?: RequestInit) => {
      if (url.includes('/api/projects/proj-alpha/findings/alpha-f-1/decision') && opts?.method === 'POST') {
        const body = JSON.parse(opts.body as string)
        alphaStatus = body.status
        alphaJustification = body.justification
        return {
          ok: true,
          status: 200,
          json: async () => ({
            project_id: 'proj-alpha',
            finding_id: 'alpha-f-1',
            status: alphaStatus,
            justification: alphaJustification,
          }),
        }
      }
      if (url.includes('/api/projects/proj-alpha/findings')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            items: [{ ...alphaFindingItem, status: alphaStatus, triage_justification: alphaJustification }],
            total: 1,
            page: 1,
            page_size: 25,
            total_pages: 1,
          }),
        }
      }
      if (url.includes('/api/projects/proj-beta/findings')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            items: [betaFindingItem],
            total: 1,
            page: 1,
            page_size: 25,
            total_pages: 1,
          }),
        }
      }
      return { ok: true, status: 200, json: async () => ({}) }
    })

    const originalFetch = globalThis.fetch
    globalThis.fetch = fetchMock as any

    try {
      const alphaFindings = await getProjectFindings('proj-alpha')
      const betaFindings = await getProjectFindings('proj-beta')

      expect(alphaFindings.items.length).toBeGreaterThan(0)
      expect(betaFindings.items.length).toBeGreaterThan(0)

      const firstAlphaFinding = alphaFindings.items[0]!
      expect(firstAlphaFinding.status).toBe('open')

      // Record decision on alpha finding
      await recordFindingDecision('proj-alpha', firstAlphaFinding.id, {
        status: 'not_affected',
        justification: 'Project 1 specific justification',
      })

      // Alpha finding reflects updated status
      const alphaAfter = await getProjectFindings('proj-alpha')
      const updatedAlpha = alphaAfter.items.find((f) => f.id === firstAlphaFinding.id)
      expect(updatedAlpha?.status).toBe('not_affected')

      // Beta findings must remain unaffected ('open')
      const betaAfter = await getProjectFindings('proj-beta')
      for (const item of betaAfter.items) {
        expect(item.status).toBe('open')
        expect(item.triage_justification).toBeFalsy()
      }
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})
