import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import {
  login as apiLogin,
  logout as apiLogout,
  me as apiMe,
  register as apiRegister,
  setUnauthorizedHandler,
} from './authApi'
import type { AuthStatus, AuthUser } from './types'

interface AuthContextValue {
  user: AuthUser | null
  status: AuthStatus
  register: (name: string, email: string, password: string) => Promise<AuthUser>
  login: (email: string, password: string) => Promise<AuthUser>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export interface AuthProviderProps {
  children: ReactNode
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [status, setStatus] = useState<AuthStatus>('checking')

  const handleUnauthorized = useCallback(() => {
    setUser(null)
    setStatus('anonymous')
  }, [])

  useEffect(() => {
    setUnauthorizedHandler(handleUnauthorized)
    return () => {
      setUnauthorizedHandler(null)
    }
  }, [handleUnauthorized])

  useEffect(() => {
    let isMounted = true

    async function checkAuth() {
      try {
        const currentUser = await apiMe()
        if (isMounted) {
          setUser(currentUser)
          setStatus('authenticated')
        }
      } catch {
        if (isMounted) {
          setUser(null)
          setStatus('anonymous')
        }
      }
    }

    void checkAuth()

    return () => {
      isMounted = false
    }
  }, [])

  const register = useCallback(
    async (name: string, email: string, password: string): Promise<AuthUser> => {
      const newUser = await apiRegister(name, email, password)
      setUser(newUser)
      setStatus('authenticated')
      return newUser
    },
    [],
  )

  const login = useCallback(async (email: string, password: string): Promise<AuthUser> => {
    const loggedInUser = await apiLogin(email, password)
    setUser(loggedInUser)
    setStatus('authenticated')
    return loggedInUser
  }, [])

  const logout = useCallback(async (): Promise<void> => {
    try {
      await apiLogout()
    } finally {
      setUser(null)
      setStatus('anonymous')
    }
  }, [])

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      status,
      register,
      login,
      logout,
    }),
    [user, status, register, login, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
