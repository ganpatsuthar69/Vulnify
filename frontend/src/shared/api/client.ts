import type { ApiClientErrorOptions, ApiErrorResponse } from '../types/api'

export class ApiClientError extends Error {
  readonly status?: number
  readonly code?: string
  readonly requestId?: string
  readonly retryAfter?: number
  readonly isNetworkError: boolean

  constructor(message: string, options?: ApiClientErrorOptions) {
    super(message)
    this.name = 'ApiClientError'
    this.status = options?.status
    this.code = options?.code
    this.requestId = options?.requestId
    this.retryAfter = options?.retryAfter
    this.isNetworkError = options?.isNetworkError ?? false
  }
}

export function getApiUrl(path: string): string {
  const baseUrl = import.meta.env.VITE_API_BASE_URL || ''
  if (!baseUrl) {
    return path.startsWith('/') ? path : `/${path}`
  }
  const cleanBase = baseUrl.replace(/\/+$/, '')
  const cleanPath = path.startsWith('/') ? path : `/${path}`
  return `${cleanBase}${cleanPath}`
}

export async function parseApiError(
  response: Response,
  fallbackMessage = 'Something went wrong. Try again.',
): Promise<{ code: string; message: string; requestId?: string }> {
  const headerRequestId = response.headers.get('x-request-id') ?? undefined

  try {
    const data = (await response.json()) as Partial<ApiErrorResponse>
    if (data && typeof data === 'object') {
      const code = typeof data.code === 'string' ? data.code : 'UNKNOWN_ERROR'
      const message = typeof data.message === 'string' ? data.message : fallbackMessage
      const requestId = typeof data.request_id === 'string' ? data.request_id : headerRequestId
      return { code, message, requestId }
    }
  } catch {
    // Malformed JSON or non-JSON error response (e.g., HTML 502/504 Bad Gateway)
  }

  // Safe fallback codes and messages based on HTTP status
  let code = 'UNKNOWN_ERROR'
  let message = fallbackMessage

  if (response.status === 401) {
    code = 'UNAUTHORIZED'
    message = 'Authentication required.'
  } else if (response.status === 403) {
    code = 'FORBIDDEN'
    message = 'Access forbidden.'
  } else if (response.status === 404) {
    code = 'NOT_FOUND'
    message = 'The requested resource was not found.'
  } else if (response.status === 409) {
    code = 'CONFLICT'
    message = 'Resource conflict.'
  } else if (response.status === 422) {
    code = 'VALIDATION_ERROR'
    message = 'Validation error. Please check your input.'
  } else if (response.status === 429) {
    code = 'RATE_LIMIT_EXCEEDED'
    message = 'Too many requests. Please try again later.'
  } else if (response.status >= 500) {
    code = 'INTERNAL_SERVER_ERROR'
    message = 'An unexpected server error occurred.'
  }

  return { code, message, requestId: headerRequestId }
}
