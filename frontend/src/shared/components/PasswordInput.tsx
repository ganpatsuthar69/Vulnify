import { Eye, EyeOff } from 'lucide-react'
import { useState, type ChangeEvent } from 'react'

interface PasswordInputProps {
  id: string
  name: string
  value: string
  onChange: (e: ChangeEvent<HTMLInputElement>) => void
  autoComplete?: string
  maxLength?: number
  required?: boolean
  placeholder?: string
  isInvalid?: boolean
  errorRegionId?: string
  ariaLabelShow?: string
  ariaLabelHide?: string
  className?: string
}

export function PasswordInput({
  id,
  name,
  value,
  onChange,
  autoComplete = 'current-password',
  maxLength = 128,
  required = true,
  placeholder = '••••••••••••',
  isInvalid = false,
  errorRegionId,
  ariaLabelShow = 'Show password',
  ariaLabelHide = 'Hide password',
  className = '',
}: PasswordInputProps) {
  const [showPassword, setShowPassword] = useState(false)

  return (
    <div className="relative mt-1.5">
      <input
        id={id}
        name={name}
        type={showPassword ? 'text' : 'password'}
        autoComplete={autoComplete}
        maxLength={maxLength}
        required={required}
        aria-required={required}
        aria-invalid={isInvalid ? 'true' : 'false'}
        aria-describedby={errorRegionId}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        className={`block w-full rounded-lg border bg-[#0b121a] px-3.5 py-2.5 pr-11 text-sm text-slate-100 placeholder-slate-400 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#38bdf8] ${
          isInvalid
            ? 'border-rose-500 ring-1 ring-rose-500'
            : 'border-slate-700/80 hover:border-slate-600'
        } ${className}`}
      />
      <button
        type="button"
        onClick={() => setShowPassword((prev) => !prev)}
        aria-label={showPassword ? ariaLabelHide : ariaLabelShow}
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
  )
}
