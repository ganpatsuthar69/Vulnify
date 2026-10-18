import type { AuthUser } from './types'
import { ApiClientError, getApiUrl, parseApiError } from '@/shared/api/client'
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

export function notifyUnauthorized(): void {
  if (unauthorizedHandler) {
    unauthorizedHandler()
  }
}

export { parseApiError }

export async function register(name: string, email: string, password: string): Promise<AuthUser> {
  const cleanedEmail = email.trim().toLowerCase()
  const cleanedName = name.trim()

  let response: Response
  try {
    response = await fetch(getApiUrl('/api/auth/register'), {
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

  let response: Response
  try {
    response = await fetch(getApiUrl('/api/auth/login'), {
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
  let response: Response
  try {
    response = await fetch(getApiUrl('/api/auth/me'), {
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
  let response: Response
  try {
    response = await fetch(getApiUrl('/api/auth/logout'), {
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
