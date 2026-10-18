import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import axe from 'axe-core'

import { PasswordInput } from '@/shared/components/PasswordInput'
import { LoginPage } from '@/features/auth/LoginPage'
import { RegisterPage } from '@/features/auth/RegisterPage'
import { AuthProvider } from '@/features/auth/AuthProvider'

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

describe('Accessibility Verification (US-902)', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    // Mock fetch for auth & project providers
    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('/api/auth/me')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ user: { id: 'usr-1', email: 'test@example.com', name: 'Tester', role: 'admin' } }),
        } as Response
      }
      if (url.includes('/api/projects')) {
        return {
          ok: true,
          status: 200,
          json: async () => [],
        } as Response
      }
      return { ok: true, status: 200, json: async () => ({}) } as Response
    })
  })

  it('scans PasswordInput in empty state without violations', async () => {
    const { container } = render(
      <main>
        <label htmlFor="test-pwd">Password</label>
        <PasswordInput id="test-pwd" name="password" value="" onChange={() => {}} />
      </main>
    )
    await assertNoA11yViolations(container)
  })

  it('scans PasswordInput in invalid error state without violations', async () => {
    const { container } = render(
      <main>
        <label htmlFor="err-pwd">Password</label>
        <PasswordInput
          id="err-pwd"
          name="password"
          value="short"
          isInvalid={true}
          errorRegionId="pwd-err"
          onChange={() => {}}
        />
        <div id="pwd-err" role="alert">Password is too short</div>
      </main>
    )
    await assertNoA11yViolations(container)
  })

  it('scans LoginPage in initial state without violations', async () => {
    const { container } = render(
      <MemoryRouter initialEntries={['/login']}>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </MemoryRouter>
    )
    await assertNoA11yViolations(container)
  })

  it('scans RegisterPage in initial state without violations', async () => {
    const { container } = render(
      <MemoryRouter initialEntries={['/register']}>
        <AuthProvider>
          <RegisterPage />
        </AuthProvider>
      </MemoryRouter>
    )
    await assertNoA11yViolations(container)
  })

  it('demonstrates scanner detection of intentional accessibility violation', async () => {
    const { container } = render(
      <main>
        {/* Missing accessible name / label */}
        <button></button>
        {/* Image without alt text */}
        <img src="/broken.png" />
      </main>
    )

    let caughtError: Error | null = null
    try {
      await assertNoA11yViolations(container)
    } catch (err) {
      caughtError = err as Error
    }

    expect(caughtError).not.toBeNull()
    expect(caughtError?.message).toContain('button-name')
    expect(caughtError?.message).toContain('image-alt')
  })
})
