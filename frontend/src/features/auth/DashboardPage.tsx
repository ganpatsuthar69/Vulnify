import { LogOut, User as UserIcon, Lock } from 'lucide-react'
import { useAuth } from './AuthProvider'
import vulnifyLogo from '@/assets/vulnify-logo.png'

export function DashboardPage() {
  const { user, logout } = useAuth()
  const isAdmin = user?.role === 'admin'

  return (
    <div className="flex min-h-screen flex-col bg-[#0b121a] text-slate-200">
      <header className="border-b border-slate-800 bg-[#0f1822]/80 px-6 py-4 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between">
          <div className="flex items-center gap-3">
            <img
              src={vulnifyLogo}
              alt="Vulnify"
              className="h-9 w-auto object-contain"
            />
            <span className="text-lg font-bold tracking-tight text-white">Vulnify</span>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-slate-300">
                {user?.name ?? 'User'}
              </span>
              <span
                className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold tracking-wide uppercase ${
                  isAdmin
                    ? 'border border-sky-400/30 bg-sky-500/10 text-sky-300'
                    : 'border border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                }`}
              >
                {user?.role ?? 'user'}
              </span>
            </div>
            <button
              type="button"
              onClick={() => void logout()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-semibold text-slate-200 transition-colors hover:border-slate-600 hover:bg-slate-700 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
              Sign out
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-6xl flex-1 flex-col justify-center p-6">
        <div className="mx-auto w-full max-w-xl rounded-xl border border-slate-800 bg-[#0f1822] p-8 shadow-xl">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-slate-800 ring-1 ring-slate-700">
              {isAdmin ? (
                <Lock className="h-6 w-6 text-sky-400" aria-hidden="true" />
              ) : (
                <UserIcon className="h-6 w-6 text-emerald-400" aria-hidden="true" />
              )}
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">{user?.name}</h2>
              <p className="text-sm text-slate-400">{user?.email}</p>
            </div>
          </div>

          <div className="mt-6 rounded-lg border border-slate-800 bg-[#0b121a] p-4">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Account Role</span>
              <span className="font-semibold text-slate-200 uppercase">{user?.role}</span>
            </div>
            <div className="mt-2 flex items-center justify-between text-xs text-slate-400">
              <span>User ID</span>
              <span className="font-mono text-slate-300">{user?.id}</span>
            </div>
          </div>

          {isAdmin ? (
            <div className="mt-6 rounded-lg border border-sky-500/20 bg-sky-500/5 p-4 text-xs text-sky-300">
              <strong>Administrator Privileges Active:</strong> You have permission to manage workspace users and promote team members via the backend CLI or administrative endpoints.
            </div>
          ) : (
            <div className="mt-6 rounded-lg border border-slate-800 bg-slate-900/40 p-4 text-xs text-slate-400">
              Standard workspace member access. Security analysis and dependency graph tools are active.
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
