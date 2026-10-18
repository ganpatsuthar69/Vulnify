import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router'
import axe from 'axe-core'

import { AppLayout } from '@/shared/components/AppLayout'
import { AuthProvider } from '@/features/auth/AuthProvider'
import { ProjectProvider } from '@/features/projects/ProjectProvider'
import { CreateProjectModal } from '@/features/projects/CreateProjectModal'
import { GitHubAdminConfigCard } from '@/features/administration/GitHubAdminConfigCard'
import { IntegrationsPage } from '@/features/administration/IntegrationsPage'
import { PlannedFeatureCard } from '@/shared/components/PlannedFeatureCard'
import { DataQualityBanner } from '@/shared/components/DataQualityBanner'
import { SessionLoader } from '@/shared/components/SessionLoader'
import type { DataQualityWarning } from '@/features/projects/types'

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

describe('App Layout and Shell Accessibility (US-902)', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/api/auth/me')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ user: mockUser }),
        } as Response
      }
      if (url.includes('/api/projects')) {
        return {
          ok: true,
          status: 200,
          json: async () => [mockProject],
        } as Response
      }
      if (url.includes('/api/admin/github-config')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            configured: true,
            repo_owner: 'vulnify',
            repo_name: 'demo-workspace',
            token_masked: 'ghp_••••••••••••••••',
            default_branch: 'main',
            created_at: 1700000000,
            updated_at: 1700000000,
          }),
        } as Response
      }
      return { ok: true, status: 200, json: async () => ({ status: 'healthy' }) } as Response
    })
  })

  it('scans AppLayout with sidebar navigation without violations', async () => {
    const { container } = render(
      <MemoryRouter initialEntries={['/']}>
        <AuthProvider>
          <ProjectProvider>
            <Routes>
              <Route element={<AppLayout />}>
                <Route path="/" element={<main><h1>Dashboard Home</h1></main>} />
              </Route>
            </Routes>
          </ProjectProvider>
        </AuthProvider>
      </MemoryRouter>
    )
    await assertNoA11yViolations(container)
  })

  it('scans CreateProjectModal open state without violations', async () => {
    const { container } = render(
      <MemoryRouter>
        <AuthProvider>
          <ProjectProvider>
            <main>
              <CreateProjectModal
                isOpen={true}
                onClose={() => {}}
              />
            </main>
          </ProjectProvider>
        </AuthProvider>
      </MemoryRouter>
    )
    await assertNoA11yViolations(container)
  })

  it('scans GitHubAdminConfigCard without violations', async () => {
    const { container } = render(
      <AuthProvider>
        <main>
          <GitHubAdminConfigCard />
        </main>
      </AuthProvider>
    )
    await assertNoA11yViolations(container)
  })

  it('scans IntegrationsPage without violations', async () => {
    const { container } = render(
      <AuthProvider>
        <ProjectProvider>
          <main>
            <IntegrationsPage />
          </main>
        </ProjectProvider>
      </AuthProvider>
    )
    await assertNoA11yViolations(container)
  })

  it('scans PlannedFeatureCard without violations', async () => {
    const { container } = render(
      <main>
        <PlannedFeatureCard
          storyId="US-502"
          title="Fix Simulation Engine"
          epic="Remediation"
          release="R2"
          persona="Security Engineer"
          description="Simulates automated package upgrades against graph dependencies."
          acceptanceCriteria={[
            'Simulate upgrade with graph path reachability check',
            'Verify no regression introduced to dependent services',
          ]}
        />
      </main>
    )
    await assertNoA11yViolations(container)
  })

  it('scans DataQualityBanner without violations', async () => {
    const warning: DataQualityWarning = {
      code: 'STALE_ADVISORY_CACHE',
      category: 'stale_advisory_data',
      severity: 'warning',
      title: 'Stale Cache',
      message: 'Advisory database cache is over 7 days old.',
    }
    const { container } = render(
      <main>
        <DataQualityBanner warnings={[warning]} />
      </main>
    )
    await assertNoA11yViolations(container)
  })

  it('scans SessionLoader without violations', async () => {
    const { container } = render(
      <main>
        <SessionLoader />
      </main>
    )
    await assertNoA11yViolations(container)
  })
})
