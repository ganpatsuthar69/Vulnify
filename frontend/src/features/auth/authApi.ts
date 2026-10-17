import type { AuthUser } from './types'
import { ApiClientError, isMockMode, parseApiError } from '@/shared/api/client'
import type { ApiClientErrorOptions } from '@/shared/types/api'

export class AuthApiError extends ApiClientError {
  constructor(message: string, options?: ApiClientErrorOptions) {
    super(message, options)
    this.name = 'AuthApiError'
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

export { parseApiError }

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

export async function register(name: string, email: string, password: string): Promise<AuthUser> {
  const cleanedEmail = email.trim().toLowerCase()
  const cleanedName = name.trim()

  if (isMockMode()) {
    if (mockUsersDatabase.has(cleanedEmail)) {
      throw new AuthApiError('An account with this email already exists.', {
        status: 409,
        code: 'CONFLICT',
        requestId: `req-mock-${Date.now()}`,
      })
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
    throw new AuthApiError('Cannot reach the server.', {
      isNetworkError: true,
      code: 'NETWORK_ERROR',
    })
  }

  if (response.status === 201) {
    return (await response.json()) as AuthUser
  }

  const errInfo = await parseApiError(response, 'Registration failed. Please try again.')
  throw new AuthApiError(errInfo.message, {
    status: response.status,
    code: errInfo.code,
    requestId: errInfo.requestId,
  })
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

    throw new AuthApiError('Invalid email or password.', {
      status: 401,
      code: 'INVALID_CREDENTIALS',
      requestId: `req-mock-${Date.now()}`,
    })
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
    throw new AuthApiError('Cannot reach the server.', {
      isNetworkError: true,
      code: 'NETWORK_ERROR',
    })
  }

  if (response.status === 200) {
    return (await response.json()) as AuthUser
  }

  const retryHeader = response.headers.get('Retry-After')
  const retrySeconds = retryHeader ? parseInt(retryHeader, 10) : undefined
  const validRetry =
    retrySeconds && !Number.isNaN(retrySeconds) && retrySeconds > 0 ? retrySeconds : undefined

  const errInfo = await parseApiError(response, 'Sign in failed. Please try again.')
  throw new AuthApiError(errInfo.message, {
    status: response.status,
    code: errInfo.code,
    requestId: errInfo.requestId,
    retryAfter: validRetry,
  })
}

export async function me(): Promise<AuthUser> {
  if (isMockMode()) {
    if (mockSessionUser) {
      return mockSessionUser
    }
    notifyUnauthorized()
    throw new AuthApiError('Authentication required.', {
      status: 401,
      code: 'AUTHENTICATION_REQUIRED',
      requestId: `req-mock-${Date.now()}`,
    })
  }

  let response: Response
  try {
    response = await fetch('/api/auth/me', {
      method: 'GET',
      credentials: 'include',
    })
  } catch {
    throw new AuthApiError('Cannot reach the server.', {
      isNetworkError: true,
      code: 'NETWORK_ERROR',
    })
  }

  if (response.status === 200) {
    return (await response.json()) as AuthUser
  }

  if (response.status === 401) {
    notifyUnauthorized()
    const errInfo = await parseApiError(response, 'Authentication required.')
    throw new AuthApiError(errInfo.message, {
      status: 401,
      code: errInfo.code,
      requestId: errInfo.requestId,
    })
  }

  const errInfo = await parseApiError(response, 'Failed to retrieve profile.')
  throw new AuthApiError(errInfo.message, {
    status: response.status,
    code: errInfo.code,
    requestId: errInfo.requestId,
  })
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
    throw new AuthApiError('Cannot reach the server.', {
      isNetworkError: true,
      code: 'NETWORK_ERROR',
    })
  }

  if (response.status === 204 || response.status === 401) {
    notifyUnauthorized()
    return
  }

  const errInfo = await parseApiError(response, 'Logout failed.')
  throw new AuthApiError(errInfo.message, {
    status: response.status,
    code: errInfo.code,
    requestId: errInfo.requestId,
  })
}
