import { useState, useEffect, useCallback } from 'react'
import {
  GitPullRequest,
  CheckCircle2,
  AlertTriangle,
  AlertCircle,
  Lock,
  RefreshCw,
  Loader2,
  ShieldCheck,
  ShieldAlert,
  Eye,
  EyeOff,
} from 'lucide-react'
import { useAuth } from '@/features/auth/AuthProvider'
import {
  getGitHubConfig,
  updateGitHubConfig,
  validateGitHubConfig,
  ProjectApiError,
} from '@/features/projects/projectApi'
import type {
  GitHubConfigResponse,
  GitHubValidationResult,
} from '@/features/projects/types'

interface GitHubAdminConfigCardProps {
  projectId?: string
  projectName?: string
  onConfigUpdated?: (config: GitHubConfigResponse) => void
}

export function GitHubAdminConfigCard({
  projectId,
  projectName,
  onConfigUpdated,
}: GitHubAdminConfigCardProps) {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  const [config, setConfig] = useState<GitHubConfigResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)

  // Form states
  const [owner, setOwner] = useState('')
  const [repo, setRepo] = useState('')
  const [token, setToken] = useState('')
  const [showTokenInput, setShowTokenInput] = useState(false)

  // Validation / Save feedback states
  const [isValidating, setIsValidating] = useState(false)
  const [validationResult, setValidationResult] = useState<GitHubValidationResult | null>(null)
  const [isSaving, setIsSaving] = useState(false)
  const [saveSuccessNotice, setSaveSuccessNotice] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)

  // Fetch current config
  const fetchConfig = useCallback(async () => {
    setIsLoading(true)
    setLoadError(null)
    try {
      const data = await getGitHubConfig(projectId)
      setConfig(data)
      setOwner(data.owner || '')
      setRepo(data.repo || '')
      setToken('')
      if (onConfigUpdated) {
        onConfigUpdated(data)
      }
    } catch (err) {
      const msg = err instanceof ProjectApiError ? err.message : 'Failed to load GitHub configuration.'
      setLoadError(msg)
    } finally {
      setIsLoading(false)
    }
  }, [projectId, onConfigUpdated])

  useEffect(() => {
    void fetchConfig()
  }, [fetchConfig])

  // Test Connection / Validate target repo access
  const handleTestConnection = async () => {
    if (!owner.trim() || !repo.trim()) {
      setActionError('Repository owner and repository name are required to test connection.')
      return
    }

    setIsValidating(true)
    setActionError(null)
    setSaveSuccessNotice(null)
    setValidationResult(null)

    try {
      const res = await validateGitHubConfig({
        owner: owner.trim(),
        repo: repo.trim(),
        token: token.trim() || undefined,
        project_id: projectId,
      })
      setValidationResult(res)
      if (!res.valid) {
        setActionError(res.message)
      }
    } catch (err) {
      const msg = err instanceof ProjectApiError ? err.message : 'Validation request failed.'
      setActionError(msg)
    } finally {
      setIsValidating(false)
    }
  }

  // Save and persist configuration
  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!owner.trim() || !repo.trim()) {
      setActionError('Repository owner and repository name are required.')
      return
    }

    setIsSaving(true)
    setActionError(null)
    setSaveSuccessNotice(null)

    try {
      const updated = await updateGitHubConfig({
        owner: owner.trim(),
        repo: repo.trim(),
        token: token.trim() || undefined,
        project_id: projectId,
        validate_before_save: true,
      })
      setConfig(updated)
      setToken('')
      setValidationResult(null)
      setSaveSuccessNotice(
        `Successfully updated GitHub target to "${updated.target_repo}". Configuration validated against GitHub REST API (US-506).`,
      )
      if (onConfigUpdated) {
        onConfigUpdated(updated)
      }
      setTimeout(() => setSaveSuccessNotice(null), 6000)
    } catch (err) {
      const msg = err instanceof ProjectApiError ? err.message : 'Failed to save GitHub configuration.'
      setActionError(msg)
    } finally {
      setIsSaving(false)
    }
  }

  if (isLoading) {
    return (
      <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl flex items-center justify-center gap-3 text-slate-400 text-xs">
        <Loader2 className="h-4 w-4 animate-spin text-sky-400" />
        <span>Loading GitHub integration configuration...</span>
      </div>
    )
  }

  if (loadError && !config) {
    return (
      <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-5 text-xs text-rose-300 space-y-2">
        <div className="flex items-center gap-2 font-semibold text-rose-200">
          <AlertCircle className="h-4 w-4 text-rose-400" />
          <span>Unable to Load GitHub Integration</span>
        </div>
        <p>{loadError}</p>
        <button
          type="button"
          onClick={() => void fetchConfig()}
          className="rounded bg-rose-500/20 px-3 py-1 font-semibold text-rose-200 hover:bg-rose-500/30 transition text-[11px]"
        >
          Retry
        </button>
      </div>
    )
  }

  const isMisconfigured = config?.validation_status === 'invalid'
  const isFullyConfigured = Boolean(config?.configured && !isMisconfigured)

  return (
    <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-6 shadow-xl space-y-6">
      {/* Header & Status Indicator */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-slate-800/80 p-2.5 text-sky-400 border border-slate-700/60">
            <GitPullRequest className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-white">GitHub Integration Target & Credentials</h2>
              <span className="rounded-full bg-sky-500/15 border border-sky-500/30 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-sky-300">
                US-506 Admin Config
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              {projectName
                ? `Target repository configuration for ${projectName}.`
                : 'Global GitHub destination repository and credential management.'}
            </p>
          </div>
        </div>

        <div>
          {isFullyConfigured ? (
            <span className="flex items-center gap-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 px-3 py-1 text-xs font-bold text-emerald-300">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              Connected &amp; Validated
            </span>
          ) : isMisconfigured ? (
            <span className="flex items-center gap-1.5 rounded-full bg-rose-500/15 border border-rose-500/30 px-3 py-1 text-xs font-bold text-rose-300">
              <AlertTriangle className="h-3.5 w-3.5 text-rose-400" />
              Misconfigured (Creation Blocked)
            </span>
          ) : (
            <span className="flex items-center gap-1.5 rounded-full bg-amber-500/15 border border-amber-500/30 px-3 py-1 text-xs font-bold text-amber-300">
              <AlertCircle className="h-3.5 w-3.5 text-amber-400" />
              Unconfigured Token
            </span>
          )}
        </div>
      </div>

      {/* Non-Sensitive Configuration Overview (Safe Display) */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
        <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 space-y-1">
          <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
            Target Repository
          </span>
          <div className="font-mono text-sky-300 font-semibold truncate select-all">
            {config?.target_repo || 'None'}
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 space-y-1">
          <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
            Token Security
          </span>
          <div className="text-slate-300 font-medium flex items-center gap-1.5">
            <Lock className="h-3 w-3 text-sky-400 shrink-0" />
            <span>{config?.has_token ? 'Encrypted (AES-256-GCM)' : 'No token stored'}</span>
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 space-y-1">
          <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
            Last Validated
          </span>
          <div className="text-slate-300 truncate">
            {config?.last_validated_at
              ? new Date(config.last_validated_at * 1000).toLocaleString()
              : 'Not yet verified'}
          </div>
        </div>
      </div>

      {/* Misconfiguration Alert (US-506 AC-2) */}
      {isMisconfigured && config?.validation_message && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-200 flex items-start gap-3">
          <ShieldAlert className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-bold text-white">Issue Creation Blocked Due to Misconfiguration:</span>
            <p className="leading-relaxed text-rose-200/90">{config.validation_message}</p>
            <p className="text-[11px] text-rose-300/80 mt-1">
              Per US-506 safety rules, remediation issues cannot be opened until target repository permissions are validated.
            </p>
          </div>
        </div>
      )}

      {/* Unconfigured Alert */}
      {!config?.has_token && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-200 flex items-start gap-3">
          <AlertCircle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-bold text-white">GitHub Token Not Configured:</span>
            <p className="leading-relaxed text-amber-200/90">
              Provide a GitHub Personal Access Token (classic or fine-grained with Issues: write permission)
              to enable live issue creation. Previews remain operational with deterministic plan hashing.
            </p>
          </div>
        </div>
      )}

      {/* Success Notification */}
      {saveSuccessNotice && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-xs text-emerald-200 flex items-center gap-2.5">
          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
          <span>{saveSuccessNotice}</span>
        </div>
      )}

      {/* Action / Validation Error */}
      {actionError && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-200 flex items-start gap-2.5">
          <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-0.5">
            <span className="font-semibold text-white">Configuration Error:</span>
            <p className="text-rose-200/90 leading-relaxed">{actionError}</p>
          </div>
        </div>
      )}

      {/* Inline Validation Result */}
      {validationResult && validationResult.valid && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-xs text-emerald-200 flex items-start gap-2.5">
          <ShieldCheck className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-bold text-white">Connection Verified Successfully:</span>
            <p className="text-emerald-200/90">{validationResult.message}</p>
            <div className="flex gap-4 pt-1 text-[11px] text-emerald-300 font-mono">
              <span>Issues Enabled: {validationResult.has_issues_enabled ? 'Yes' : 'No'}</span>
              <span>Write/Push Permission: {validationResult.has_write_access ? 'Yes' : 'No'}</span>
            </div>
          </div>
        </div>
      )}

      {/* Admin Configuration Form (RBAC: Admin Only) */}
      {isAdmin ? (
        <form onSubmit={handleSaveConfig} className="space-y-4 border-t border-slate-800/80 pt-5">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Owner / Org */}
            <div className="space-y-1.5">
              <label htmlFor="gh-owner" className="block text-xs font-semibold text-slate-300">
                GitHub Owner / Organization <span className="text-rose-400">*</span>
              </label>
              <input
                id="gh-owner"
                type="text"
                value={owner}
                onChange={(e) => setOwner(e.target.value)}
                placeholder="e.g. vulnify or your-org"
                required
                className="w-full rounded-lg border border-slate-700 bg-slate-900/90 px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 font-mono"
              />
              <span className="text-[10px] text-slate-500">
                The GitHub user or organization account owning the destination repository.
              </span>
            </div>

            {/* Repository Name */}
            <div className="space-y-1.5">
              <label htmlFor="gh-repo" className="block text-xs font-semibold text-slate-300">
                Repository Name <span className="text-rose-400">*</span>
              </label>
              <input
                id="gh-repo"
                type="text"
                value={repo}
                onChange={(e) => setRepo(e.target.value)}
                placeholder="e.g. demo-workspace or repo-name"
                required
                className="w-full rounded-lg border border-slate-700 bg-slate-900/90 px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 font-mono"
              />
              <span className="text-[10px] text-slate-500">
                The repository where Vulnify remediation issues will be opened.
              </span>
            </div>
          </div>

          {/* Personal Access Token (PAT) with Masking and Rotation */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label htmlFor="gh-token" className="block text-xs font-semibold text-slate-300">
                Personal Access Token (PAT)
              </label>
              {config?.has_token && (
                <span className="text-[10px] text-emerald-400 font-medium flex items-center gap-1">
                  <CheckCircle2 className="h-3 w-3" />
                  Token is currently configured
                </span>
              )}
            </div>

            <div className="relative">
              <input
                id="gh-token"
                type={showTokenInput ? 'text' : 'password'}
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder={
                  config?.has_token
                    ? 'Leave blank to keep existing token, or enter a new token to rotate'
                    : 'Enter GitHub Personal Access Token (e.g. ghp_...)'
                }
                autoComplete="new-password"
                className="w-full rounded-lg border border-slate-700 bg-slate-900/90 pl-3.5 pr-10 py-2 text-xs text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500 font-mono"
              />
              <button
                type="button"
                onClick={() => setShowTokenInput(!showTokenInput)}
                aria-label={showTokenInput ? 'Hide token' : 'Show token'}
                className="absolute inset-y-0 right-0 flex items-center px-3 text-slate-400 hover:text-white"
              >
                {showTokenInput ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
              </button>
            </div>

            <div className="flex items-center gap-1.5 text-[10px] text-slate-500">
              <Lock className="h-3 w-3 text-sky-400 shrink-0" />
              <span>
                Tokens are encrypted with AES-256-GCM. Vulnify never displays existing token values in responses or HTML.
              </span>
            </div>
          </div>

          {/* Target Preview */}
          {owner.trim() && repo.trim() && (
            <div className="rounded-lg border border-slate-800 bg-[#0b121a] p-3 text-xs flex items-center justify-between">
              <span className="text-slate-400">Target Destination Preview:</span>
              <code className="font-mono text-sky-400 font-bold bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800">
                https://github.com/{owner.trim()}/{repo.trim()}/issues
              </code>
            </div>
          )}

          {/* Form Actions */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-end gap-3 pt-3">
            <button
              type="button"
              onClick={handleTestConnection}
              disabled={isValidating || isSaving || !owner.trim() || !repo.trim()}
              className="flex items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2 text-xs font-semibold text-slate-200 hover:border-sky-500 hover:text-white disabled:opacity-50 transition"
            >
              {isValidating ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Testing Access...
                </>
              ) : (
                <>
                  <RefreshCw className="h-3.5 w-3.5 text-sky-400" />
                  Test Connection
                </>
              )}
            </button>

            <button
              type="submit"
              disabled={isSaving || isValidating || !owner.trim() || !repo.trim()}
              className="flex items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-50 transition shadow-lg shadow-sky-600/20"
            >
              {isSaving ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Validating &amp; Saving...
                </>
              ) : (
                <>
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  Save &amp; Validate Target
                </>
              )}
            </button>
          </div>
        </form>
      ) : (
        /* Read-only view for standard users */
        <div className="rounded-lg border border-slate-800/90 bg-[#0b121a] p-4 text-xs text-slate-400 flex items-center gap-2.5">
          <Lock className="h-4 w-4 text-slate-500 shrink-0" />
          <span>
            You are signed in as a standard user. Modifying target repository and integration credentials requires administrator privileges.
          </span>
        </div>
      )}
    </div>
  )
}
