import { Loader2 } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { Link, Navigate, useLocation, useNavigate, type Location } from 'react-router'
import { AuthApiError } from './authApi'
import { useAuth } from './AuthProvider'
import { PasswordInput } from '@/shared/components/PasswordInput'
import { SessionLoader } from '@/shared/components/SessionLoader'
import vulnifyLogo from '@/assets/vulnify-logo.png'

export function LoginPage() {
  const { status, login } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [errorRequestId, setErrorRequestId] = useState<string | null>(null)
  const [emailInvalid, setEmailInvalid] = useState(false)
  const [passwordInvalid, setPasswordInvalid] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [countdown, setCountdown] = useState<number>(0)

  // Safely resolve redirect path: only same-site paths (starts with "/" and not "//"), otherwise "/"
  const state = location.state as { from?: Location | string } | null
  const rawFrom =
    typeof state?.from === 'string'
      ? state.from
      : state?.from?.pathname
        ? state.from.pathname + (state.from.search || '')
        : '/'
  const safeFrom = rawFrom.startsWith('/') && !rawFrom.startsWith('//') ? rawFrom : '/'

  // Countdown timer for 429 Too Many Attempts
  useEffect(() => {
    if (countdown <= 0) return

    const timer = window.setTimeout(() => {
      setCountdown((prev) => {
        const next = prev - 1
        if (next <= 0) {
          setErrorMessage(null)
          return 0
        }
        setErrorMessage(`Too many attempts. Try again in ${next}s.`)
        return next
      })
    }, 1000)

    return () => {
      window.clearTimeout(timer)
    }
  }, [countdown])

  // If already authenticated, redirect to "/" (or saved from destination)
  if (status === 'authenticated') {
    return <Navigate to={safeFrom} replace />
  }

  // If checking authentication status, show accessible loader
  if (status === 'checking') {
    return <SessionLoader />
  }

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()

    if (isSubmitting || countdown > 0) {
      return
    }

    const trimmedEmail = email.trim()
    const isEmailMissing = trimmedEmail.length === 0
    const isPassMissing = password.length === 0

    // Set aria-invalid flags
    setEmailInvalid(isEmailMissing)
    setPasswordInvalid(isPassMissing)

    if (isEmailMissing || isPassMissing) {
      setPassword('')
      setErrorMessage('Invalid email or password.')
      return
    }

    setIsSubmitting(true)
    setErrorMessage(null)
    setErrorRequestId(null)

    try {
      await login(trimmedEmail, password)
      navigate(safeFrom, { replace: true })
    } catch (err: unknown) {
      setPassword('')

      if (err instanceof AuthApiError) {
        if (err.requestId) {
          setErrorRequestId(err.requestId)
        }
        if (err.status === 401) {
          setErrorMessage('Invalid email or password.')
        } else if (err.status === 429) {
          const waitTime = err.retryAfter ?? 60
          setCountdown(waitTime)
          setErrorMessage(`Too many attempts. Try again in ${waitTime}s.`)
        } else if (err.isNetworkError) {
          setErrorMessage('Cannot reach the server.')
        } else {
          setErrorMessage(err.message || 'Something went wrong. Try again.')
        }
      } else {
        setErrorMessage('Something went wrong. Try again.')
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#0b121a] px-4 py-12 text-slate-200">
      <div className="w-full max-w-md rounded-xl border border-slate-800 bg-[#0f1822] p-8 shadow-2xl shadow-black/60">

        {/* Header with Vulnify logo */}
        <div className="mb-8 text-center">
          <img
            src={vulnifyLogo}
            alt="Vulnify"
            className="mx-auto h-16 w-auto object-contain"
          />
          <h1 className="mt-4 text-2xl font-bold tracking-tight text-white">Vulnify</h1>
          <p className="mt-1 text-sm font-medium text-slate-400">Sign in to your security workspace</p>
        </div>

        {/* Real <form> so Enter submits */}
        <form onSubmit={handleSubmit} noValidate className="space-y-5">
          {/* Email */}
          <div>
            <label htmlFor="email" className="block text-xs font-medium uppercase tracking-wider text-slate-300">
              Email Address
            </label>
            <input
              id="email"
              name="email"
              type="email"
              autoFocus
              autoComplete="email"
              maxLength={255}
              required
              aria-required="true"
              aria-invalid={emailInvalid ? 'true' : 'false'}
              aria-describedby={errorMessage ? 'login-error-region' : undefined}
              value={email}
              onChange={(e) => {
                setEmail(e.target.value)
                if (emailInvalid) setEmailInvalid(false)
              }}
              placeholder="user@example.com"
              className={`mt-1.5 block w-full rounded-lg border bg-[#0b121a] px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-400 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#38bdf8] ${
                emailInvalid ? 'border-rose-500 ring-1 ring-rose-500' : 'border-slate-700/80 hover:border-slate-600'
              }`}
            />
          </div>

          {/* Password */}
          <div>
            <label htmlFor="password" className="block text-xs font-medium uppercase tracking-wider text-slate-300">
              Password
            </label>
            <PasswordInput
              id="password"
              name="password"
              autoComplete="current-password"
              isInvalid={passwordInvalid}
              errorRegionId={errorMessage ? 'login-error-region' : undefined}
              value={password}
              onChange={(e) => {
                setPassword(e.target.value)
                if (passwordInvalid) setPasswordInvalid(false)
              }}
            />
          </div>

          {/* Error handling: an aria-live="polite" region above the button */}
          <div
            id="login-error-region"
            aria-live="polite"
            className="min-h-[1.5rem] text-sm font-medium text-rose-400"
          >
            {errorMessage ? (
              <div>
                <p>{errorMessage}</p>
                {errorRequestId && (
                  <p className="mt-1 font-mono text-xs text-slate-400">
                    Request ID: {errorRequestId}
                  </p>
                )}
              </div>
            ) : null}
          </div>

          {/* Submit button */}
          <button
            type="submit"
            disabled={isSubmitting || countdown > 0}
            className="flex w-full items-center justify-center rounded-lg bg-[#38bdf8] px-4 py-2.5 text-sm font-semibold text-slate-950 transition-all hover:bg-sky-400 active:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#38bdf8] focus-visible:ring-offset-2 focus-visible:ring-offset-[#0f1822]"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin text-slate-950" aria-hidden="true" />
                <span>Signing in...</span>
              </>
            ) : countdown > 0 ? (
              <span>Locked ({countdown}s)</span>
            ) : (
              <span>Sign in</span>
            )}
          </button>
        </form>

        {/* Link to Registration */}
        <div className="mt-6 text-center text-sm text-slate-400">
          Don't have an account?{' '}
          <Link
            to="/register"
            className="font-medium text-sky-400 hover:text-sky-300 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 rounded"
          >
            Create an account
          </Link>
        </div>
      </div>
    </div>
  )
}
