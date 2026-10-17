import { Eye, EyeOff, Loader2 } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Link, Navigate, useNavigate } from 'react-router'
import { AuthApiError } from './authApi'
import { useAuth } from './AuthProvider'
import vulnifyLogo from '@/assets/vulnify-logo.png'

const EMAIL_REGEX = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/

export function RegisterPage() {
  const { status, register } = useAuth()
  const navigate = useNavigate()

  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)

  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [nameInvalid, setNameInvalid] = useState(false)
  const [emailInvalid, setEmailInvalid] = useState(false)
  const [passwordInvalid, setPasswordInvalid] = useState(false)
  const [confirmInvalid, setConfirmInvalid] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  const isMockMode = import.meta.env.VITE_USE_MOCK === 'true'

  if (status === 'authenticated') {
    return <Navigate to="/" replace />
  }

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

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()

    if (isSubmitting) return

    const trimmedName = name.trim()
    const trimmedEmail = email.trim()

    // Validate inputs
    const isNameBad = trimmedName.length === 0
    const isEmailBad = !EMAIL_REGEX.test(trimmedEmail)
    const isPassBad = password.length < 8
    const isConfirmBad = password !== confirmPassword

    setNameInvalid(isNameBad)
    setEmailInvalid(isEmailBad)
    setPasswordInvalid(isPassBad)
    setConfirmInvalid(isConfirmBad)

    if (isNameBad) {
      setErrorMessage('Please enter your full name.')
      return
    }

    if (isEmailBad) {
      setErrorMessage('Please enter a valid email address.')
      return
    }

    if (isPassBad) {
      setErrorMessage('Password must be at least 8 characters long.')
      return
    }

    if (isConfirmBad) {
      setErrorMessage('Passwords do not match.')
      return
    }

    setIsSubmitting(true)
    setErrorMessage(null)

    try {
      await register(trimmedName, trimmedEmail, password)
      navigate('/', { replace: true })
    } catch (err: unknown) {
      setPassword('')
      setConfirmPassword('')

      if (err instanceof AuthApiError) {
        if (err.status === 409) {
          setErrorMessage('An account with this email already exists.')
        } else if (err.isNetworkError) {
          setErrorMessage('Cannot reach the server.')
        } else {
          setErrorMessage(err.message || 'Registration failed. Please check your details.')
        }
      } else {
        setErrorMessage('Something went wrong. Please try again.')
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#0b121a] px-4 py-12 text-slate-200">
      <div className="w-full max-w-md rounded-xl border border-slate-800 bg-[#0f1822] p-8 shadow-2xl shadow-black/60">
        {isMockMode && (
          <div
            role="note"
            className="mb-6 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-center text-xs font-semibold tracking-wider text-amber-300 uppercase"
          >
            Mock registration mode
          </div>
        )}

        {/* Header with Vulnify logo */}
        <div className="mb-8 text-center">
          <img
            src={vulnifyLogo}
            alt="Vulnify"
            className="mx-auto h-16 w-auto object-contain"
          />
          <h1 className="mt-4 text-2xl font-bold tracking-tight text-white">Vulnify</h1>
          <p className="mt-1 text-sm font-medium text-slate-400">Create your security workspace account</p>
        </div>

        {/* Real <form> so Enter submits */}
        <form onSubmit={handleSubmit} noValidate className="space-y-4">
          {/* Full Name */}
          <div>
            <label htmlFor="name" className="block text-xs font-medium uppercase tracking-wider text-slate-300">
              Full Name
            </label>
            <input
              id="name"
              name="name"
              type="text"
              autoFocus
              autoComplete="name"
              maxLength={100}
              required
              aria-required="true"
              aria-invalid={nameInvalid ? 'true' : 'false'}
              aria-describedby={errorMessage ? 'register-error-region' : undefined}
              value={name}
              onChange={(e) => {
                setName(e.target.value)
                if (nameInvalid) setNameInvalid(false)
              }}
              placeholder="Alex Analyst"
              className={`mt-1.5 block w-full rounded-lg border bg-[#0b121a] px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-400 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#38bdf8] ${
                nameInvalid ? 'border-rose-500 ring-1 ring-rose-500' : 'border-slate-700/80 hover:border-slate-600'
              }`}
            />
          </div>

          {/* Email */}
          <div>
            <label htmlFor="email" className="block text-xs font-medium uppercase tracking-wider text-slate-300">
              Email Address
            </label>
            <input
              id="email"
              name="email"
              type="email"
              autoComplete="email"
              maxLength={255}
              required
              aria-required="true"
              aria-invalid={emailInvalid ? 'true' : 'false'}
              aria-describedby={errorMessage ? 'register-error-region' : undefined}
              value={email}
              onChange={(e) => {
                setEmail(e.target.value)
                if (emailInvalid) setEmailInvalid(false)
              }}
              placeholder="alex@example.com"
              className={`mt-1.5 block w-full rounded-lg border bg-[#0b121a] px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-400 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#38bdf8] ${
                emailInvalid ? 'border-rose-500 ring-1 ring-rose-500' : 'border-slate-700/80 hover:border-slate-600'
              }`}
            />
          </div>

          {/* Password */}
          <div>
            <label htmlFor="password" className="block text-xs font-medium uppercase tracking-wider text-slate-300">
              Password (min. 8 characters)
            </label>
            <div className="relative mt-1.5">
              <input
                id="password"
                name="password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="new-password"
                maxLength={128}
                required
                aria-required="true"
                aria-invalid={passwordInvalid ? 'true' : 'false'}
                aria-describedby={errorMessage ? 'register-error-region' : undefined}
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value)
                  if (passwordInvalid) setPasswordInvalid(false)
                }}
                placeholder="••••••••••••"
                className={`block w-full rounded-lg border bg-[#0b121a] px-3.5 py-2.5 pr-11 text-sm text-slate-100 placeholder-slate-400 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#38bdf8] ${
                  passwordInvalid ? 'border-rose-500 ring-1 ring-rose-500' : 'border-slate-700/80 hover:border-slate-600'
                }`}
              />
              <button
                type="button"
                onClick={() => setShowPassword((prev) => !prev)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                aria-pressed={showPassword}
                className="absolute inset-y-0 right-0 flex items-center px-3.5 text-slate-400 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#38bdf8] rounded-r-lg"
              >
                {showPassword ? (
                  <EyeOff className="h-4 w-4" aria-hidden="true" />
                ) : (
                  <Eye className="h-4 w-4" aria-hidden="true" />
                )}
              </button>
            </div>
          </div>

          {/* Confirm Password */}
          <div>
            <label htmlFor="confirmPassword" className="block text-xs font-medium uppercase tracking-wider text-slate-300">
              Confirm Password
            </label>
            <div className="relative mt-1.5">
              <input
                id="confirmPassword"
                name="confirmPassword"
                type={showConfirmPassword ? 'text' : 'password'}
                autoComplete="new-password"
                maxLength={128}
                required
                aria-required="true"
                aria-invalid={confirmInvalid ? 'true' : 'false'}
                aria-describedby={errorMessage ? 'register-error-region' : undefined}
                value={confirmPassword}
                onChange={(e) => {
                  setConfirmPassword(e.target.value)
                  if (confirmInvalid) setConfirmInvalid(false)
                }}
                placeholder="••••••••••••"
                className={`block w-full rounded-lg border bg-[#0b121a] px-3.5 py-2.5 pr-11 text-sm text-slate-100 placeholder-slate-400 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#38bdf8] ${
                  confirmInvalid ? 'border-rose-500 ring-1 ring-rose-500' : 'border-slate-700/80 hover:border-slate-600'
                }`}
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword((prev) => !prev)}
                aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}
                aria-pressed={showConfirmPassword}
                className="absolute inset-y-0 right-0 flex items-center px-3.5 text-slate-400 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#38bdf8] rounded-r-lg"
              >
                {showConfirmPassword ? (
                  <EyeOff className="h-4 w-4" aria-hidden="true" />
                ) : (
                  <Eye className="h-4 w-4" aria-hidden="true" />
                )}
              </button>
            </div>
          </div>

          {/* Error handling: an aria-live="polite" region */}
          <div
            id="register-error-region"
            aria-live="polite"
            className="min-h-[1.5rem] text-sm font-medium text-rose-400"
          >
            {errorMessage ? <p>{errorMessage}</p> : null}
          </div>

          {/* Submit button */}
          <button
            type="submit"
            disabled={isSubmitting}
            className="flex w-full items-center justify-center rounded-lg bg-[#38bdf8] px-4 py-2.5 text-sm font-semibold text-slate-950 transition-all hover:bg-sky-400 active:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#38bdf8] focus-visible:ring-offset-2 focus-visible:ring-offset-[#0f1822]"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin text-slate-950" aria-hidden="true" />
                <span>Creating account...</span>
              </>
            ) : (
              <span>Create account</span>
            )}
          </button>
        </form>

        {/* Link to Login */}
        <div className="mt-6 text-center text-sm text-slate-400">
          Already have an account?{' '}
          <Link
            to="/login"
            className="font-medium text-sky-400 hover:text-sky-300 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 rounded"
          >
            Sign in
          </Link>
        </div>
      </div>
    </div>
  )
}
