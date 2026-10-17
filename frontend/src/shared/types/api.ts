export interface ApiErrorResponse {
  code: string
  message: string
  request_id: string
}

export type ApiErrorPayload = ApiErrorResponse

export interface ApiClientErrorOptions {
  status?: number
  code?: string
  requestId?: string
  retryAfter?: number
  isNetworkError?: boolean
}
