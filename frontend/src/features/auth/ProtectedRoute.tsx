import { Loader2 } from 'lucide-react'
import { Navigate, Outlet, useLocation } from 'react-router'
import { useAuth } from './AuthProvider'

export function ProtectedRoute() {
  const { status } = useAuth()
  const location = useLocation()

  if (status === 'checking') {
    return (
      <div
        role="status"
        aria-live="polite"
        className="flex min-h-screen flex-col items-center justify-center bg-[#0b121a] text-slate-300"
      >
        <Loader2 className="h-8 w-8 animate-spin text-sky-400" aria-hidden="true" />
        <span className="mt-4 text-sm font-medium text-slate-300">
          Checking security session...
        </span>
      </div>
    )
  }

  if (status === 'anonymous') {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return <Outlet />
}
