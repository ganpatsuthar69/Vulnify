export type UserRole = 'user' | 'admin'

export interface AuthUser {
  id: string
  email: string
  name: string
  role: UserRole
}

// Backward compatibility alias
export type AdminUser = AuthUser

export type AuthStatus = 'checking' | 'authenticated' | 'anonymous'

export interface AuthErrorDetails {
  status?: number
  message?: string
  retryAfter?: number
  isNetworkError?: boolean
}
