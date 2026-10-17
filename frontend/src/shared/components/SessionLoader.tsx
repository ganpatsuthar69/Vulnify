import { Loader2 } from 'lucide-react'

interface SessionLoaderProps {
  message?: string
}

export function SessionLoader({ message = 'Checking security session...' }: SessionLoaderProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex min-h-screen flex-col items-center justify-center bg-[#0b121a] text-slate-300"
    >
      <Loader2 className="h-8 w-8 animate-spin text-sky-400" aria-hidden="true" />
      <span className="mt-4 text-sm font-medium text-slate-300">{message}</span>
    </div>
  )
}
