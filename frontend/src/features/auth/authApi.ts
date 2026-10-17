import type { AuthUser } from './types'

export class AuthApiError extends Error {
  readonly status?: number
  readonly retryAfter?: number
  readonly isNetworkError: boolean

  constructor(
    message: string,
    options?: { status?: number; retryAfter?: number; isNetworkError?: boolean },
  ) {
    super(message)
    this.name = 'AuthApiError'
    this.status = options?.status
    this.retryAfter = options?.retryAfter
    this.isNetworkError = options?.isNetworkError ?? false
  }
}

type UnauthorizedHandler = () => void
let unauthorizedHandler: UnauthorizedHandler | null = null

export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  unauthorizedHandler = handler
}

function notifyUnauthorized(): void {
  if (unauthorizedHandler) {
    unauthorizedHandler()
  }
}

// In-memory mock storage when VITE_USE_MOCK=true
interface MockStoredUser {
  id: string
  email: string
  name: string
  password: string
  role: 'user' | 'admin'
}

const mockUsersDatabase = new Map<string, MockStoredUser>()
let mockSessionUser: AuthUser | null = null

function isMockMode(): boolean {
  return import.meta.env.VITE_USE_MOCK === 'true'
}

export async function register(name: string, email: string, password: string): Promise<AuthUser> {
  const cleanedEmail = email.trim().toLowerCase()
  const cleanedName = name.trim()

  if (isMockMode()) {
    if (mockUsersDatabase.has(cleanedEmail)) {
      throw new AuthApiError('An account with this email already exists.', { status: 409 })
    }
    const newUser: MockStoredUser = {
      id: `mock-user-${Date.now()}`,
      email: cleanedEmail,
      name: cleanedName,
      password,
      role: 'user',
    }
    mockUsersDatabase.set(cleanedEmail, newUser)
    mockSessionUser = {
      id: newUser.id,
      email: newUser.email,
      name: newUser.name,
      role: newUser.role,
    }
    return mockSessionUser
  }

  let response: Response
  try {
    response = await fetch('/api/auth/register', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'vulnify',
      },
      body: JSON.stringify({ name: cleanedName, email: cleanedEmail, password }),
    })
  } catch {
    throw new AuthApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 201) {
    return (await response.json()) as AuthUser
  }

  if (response.status === 409) {
    throw new AuthApiError('An account with this email already exists.', { status: 409 })
  }

  if (response.status === 422) {
    try {
      const errorJson = (await response.json()) as { detail?: Array<{ msg: string }> | string }
      if (Array.isArray(errorJson.detail) && errorJson.detail.length > 0) {
        throw new AuthApiError(errorJson.detail[0]?.msg ?? 'Invalid registration data.', { status: 422 })
      }
    } catch {
      // Fall through to general error
    }
    throw new AuthApiError('Invalid registration data.', { status: 422 })
  }

  throw new AuthApiError('Something went wrong. Try again.', { status: response.status })
}

export async function login(email: string, password: string): Promise<AuthUser> {
  const cleanedEmail = email.trim().toLowerCase()

  if (isMockMode()) {
    const existing = mockUsersDatabase.get(cleanedEmail)
    // If mock mode is used without prior registration, allow admin demo credentials if configured
    const configuredMockPassword = import.meta.env.VITE_MOCK_ADMIN_PASSWORD
    if (
      configuredMockPassword &&
      (cleanedEmail === 'admin@vulnify.local' || cleanedEmail === 'admin') &&
      password === configuredMockPassword
    ) {
      mockSessionUser = {
        id: 'mock-admin-1',
        email: 'admin@vulnify.local',
        name: 'Administrator',
        role: 'admin',
      }
      return mockSessionUser
    }

    if (existing && existing.password === password) {
      mockSessionUser = {
        id: existing.id,
        email: existing.email,
        name: existing.name,
        role: existing.role,
      }
      return mockSessionUser
    }

    throw new AuthApiError('Invalid email or password.', { status: 401 })
  }

  let response: Response
  try {
    response = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'vulnify',
      },
      body: JSON.stringify({ email: cleanedEmail, password }),
    })
  } catch {
    throw new AuthApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as AuthUser
  }

  if (response.status === 401) {
    throw new AuthApiError('Invalid email or password.', { status: 401 })
  }

  if (response.status === 429) {
    const retryHeader = response.headers.get('Retry-After')
    const retrySeconds = retryHeader ? parseInt(retryHeader, 10) : 60
    const validRetry = !Number.isNaN(retrySeconds) && retrySeconds > 0 ? retrySeconds : 60
    throw new AuthApiError(`Too many attempts. Try again in ${validRetry}s.`, {
      status: 429,
      retryAfter: validRetry,
    })
  }

  throw new AuthApiError('Something went wrong. Try again.', { status: response.status })
}

export async function me(): Promise<AuthUser> {
  if (isMockMode()) {
    if (mockSessionUser) {
      return mockSessionUser
    }
    notifyUnauthorized()
    throw new AuthApiError('Unauthorized', { status: 401 })
  }

  let response: Response
  try {
    response = await fetch('/api/auth/me', {
      method: 'GET',
      credentials: 'include',
    })
  } catch {
    throw new AuthApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 200) {
    return (await response.json()) as AuthUser
  }

  if (response.status === 401) {
    notifyUnauthorized()
    throw new AuthApiError('Unauthorized', { status: 401 })
  }

  throw new AuthApiError('Something went wrong. Try again.', { status: response.status })
}

export async function logout(): Promise<void> {
  if (isMockMode()) {
    mockSessionUser = null
    notifyUnauthorized()
    return
  }

  let response: Response
  try {
    response = await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'X-Requested-With': 'vulnify',
      },
    })
  } catch {
    throw new AuthApiError('Cannot reach the server.', { isNetworkError: true })
  }

  if (response.status === 204 || response.status === 401) {
    notifyUnauthorized()
    return
  }

  throw new AuthApiError('Something went wrong. Try again.', { status: response.status })
}
