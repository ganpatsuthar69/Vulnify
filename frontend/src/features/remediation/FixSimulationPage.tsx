import { useState, useEffect, useCallback } from 'react'
import {
  FlaskConical,
  Layers,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  Clock,
  GitPullRequest,
  RefreshCw,
  Loader2,
  Info,
  Network,
  RotateCcw,
  Check,
  ExternalLink,
} from 'lucide-react'
import { useSearchParams, Link } from 'react-router'
import { useProjects } from '@/features/projects/ProjectProvider'
import {
  simulateFix,
  getProjectSimulations,
  getFindingUpgradeCandidates,
  getProjectFindings,
  ProjectApiError,
} from '@/features/projects/projectApi'
import type {
  SimulationResponse,
  SimulationRequest,
  FindingItem,
} from '@/features/projects/types'

export function FixSimulationPage() {
  const { activeProject } = useProjects()
  const [searchParams] = useSearchParams()

  const initialFindingId = searchParams.get('finding') || ''
  const initialTargetVer = searchParams.get('target') || ''
  const initialPkg = searchParams.get('package') || ''
  const initialCurrVer = searchParams.get('version') || ''

  // Form State
  const [findingId, setFindingId] = useState(initialFindingId)
  const [packageName, setPackageName] = useState(initialPkg)
  const [currentVersion, setCurrentVersion] = useState(initialCurrVer)
  const [targetVersion, setTargetVersion] = useState(initialTargetVer)
  const [ecosystem, setEcosystem] = useState(activeProject?.ecosystem || 'npm')

  // Available findings for quick selection
  const [findingsList, setFindingsList] = useState<FindingItem[]>([])
  const [findingsLoading, setFindingsLoading] = useState(false)

  // Simulation execution state
  const [simulation, setSimulation] = useState<SimulationResponse | null>(null)
  const [isSimulating, setIsSimulating] = useState(false)
  const [simError, setSimError] = useState<string | null>(null)

  // Recent simulations history
  const [history, setHistory] = useState<SimulationResponse[]>([])
  const [historyLoading, setHistoryLoading] = useState(false)

  // Load project findings for the selector
  useEffect(() => {
    if (!activeProject) {
      setFindingsList([])
      return
    }

    let isMounted = true
    setFindingsLoading(true)

    getProjectFindings(activeProject.id, { page_size: 100 })
      .then((res) => {
        if (isMounted) {
          setFindingsList(res.items)
        }
      })
      .catch(() => {
        // Non-critical: user can still enter details manually
      })
      .finally(() => {
        if (isMounted) setFindingsLoading(false)
      })

    return () => {
      isMounted = false
    }
  }, [activeProject])

  // Load recent simulations history
  const loadHistory = useCallback(async (projectId: string) => {
    setHistoryLoading(true)
    try {
      const res = await getProjectSimulations(projectId)
      setHistory(res.items)
    } catch {
      // Non-critical
    } finally {
      setHistoryLoading(false)
    }
  }, [])

  useEffect(() => {
    if (activeProject) {
      void loadHistory(activeProject.id)
    } else {
      setHistory([])
    }
  }, [activeProject, loadHistory])

  // If URL has finding or candidate pre-populated, load candidate info
  useEffect(() => {
    if (!activeProject || !initialFindingId) return

    let isMounted = true

    getFindingUpgradeCandidates(activeProject.id, initialFindingId)
      .then((res) => {
        if (!isMounted) return
        setPackageName(res.package_name)
        setCurrentVersion(res.current_version)
        setEcosystem(res.ecosystem)
        if (initialTargetVer) {
          setTargetVersion(initialTargetVer)
        } else if (res.candidates.length > 0) {
          const rec = res.candidates.find((c) => c.is_recommended) || res.candidates[0]
          setTargetVersion(rec.target_version)
        }
      })
      .catch(() => {
        // Fallback to finding from list if available
        const found = findingsList.find((f) => f.id === initialFindingId)
        if (found && isMounted) {
          setPackageName(found.package_name)
          setCurrentVersion(found.package_version)
          setEcosystem(found.ecosystem)
          if (found.fixed_version && !initialTargetVer) {
            setTargetVersion(found.fixed_version)
          }
        }
      })

    return () => {
      isMounted = false
    }
  }, [activeProject, initialFindingId, initialTargetVer, findingsList])

  // Handle Finding dropdown selection
  const handleSelectFinding = (selectedFindingId: string) => {
    setFindingId(selectedFindingId)
    setSimError(null)

    if (!selectedFindingId) return

    const f = findingsList.find((item) => item.id === selectedFindingId)
    if (f) {
      setPackageName(f.package_name)
      setCurrentVersion(f.package_version)
      setEcosystem(f.ecosystem)
      if (f.fixed_version) {
        setTargetVersion(f.fixed_version)
      }

      // Fetch recommended upgrade candidates for this finding
      if (activeProject) {
        getFindingUpgradeCandidates(activeProject.id, f.id)
          .then((res) => {
            if (res.candidates.length > 0) {
              const rec = res.candidates.find((c) => c.is_recommended) || res.candidates[0]
              setTargetVersion(rec.target_version)
            }
          })
          .catch(() => {})
      }
    }
  }

  // Run Simulation
  const handleRunSimulation = async (e?: React.FormEvent) => {
    if (e) e.preventDefault()
    if (!activeProject) return

    if (!packageName.trim() || !currentVersion.trim() || !targetVersion.trim()) {
      setSimError('Please specify package name, current version, and target version.')
      return
    }

    setIsSimulating(true)
    setSimError(null)

    const payload: SimulationRequest = {
      finding_id: findingId || null,
      package_name: packageName.trim(),
      current_version: currentVersion.trim(),
      target_version: targetVersion.trim(),
      ecosystem: ecosystem || 'npm',
    }

    try {
      const result = await simulateFix(activeProject.id, payload)
      setSimulation(result)
      void loadHistory(activeProject.id)
    } catch (err) {
      if (err instanceof ProjectApiError) {
        setSimError(err.message)
      } else {
        setSimError('Failed to execute fix simulation on server.')
      }
    } finally {
      setIsSimulating(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              <FlaskConical className="h-6 w-6 text-sky-400" />
              Fix Simulation
            </h1>
            <span className="rounded-full bg-sky-500/15 border border-sky-500/30 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-sky-300">
              US-501 &bull; Graph Overlay
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Simulate proposed dependency upgrades on an isolated FalkorDB graph overlay. Evaluates cleared findings, residual exposure, and SemVer breaking risk without mutating stored graph state.
          </p>
        </div>

        {activeProject && (
          <div className="flex items-center gap-2 self-start sm:self-auto rounded-lg border border-slate-800 bg-[#0f1822] px-3 py-1.5 text-xs text-slate-300">
            <span className="text-slate-500">Project:</span>
            <span className="font-semibold text-white">{activeProject.name}</span>
          </div>
        )}
      </div>

      {!activeProject ? (
        <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-8 text-center text-slate-400">
          <p className="text-sm font-semibold text-slate-300">No Active Project Selected</p>
          <p className="mt-1 text-xs text-slate-400">Select or create a project from the top navigation to run simulations.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Simulation Form & History */}
          <div className="space-y-6 lg:col-span-1">
            {/* Simulation Parameter Card */}
            <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h2 className="text-sm font-bold text-white flex items-center gap-2">
                  <Layers className="h-4 w-4 text-sky-400" />
                  Simulation Parameters
                </h2>
                <span className="text-[10px] font-medium text-emerald-400 bg-emerald-950/40 border border-emerald-500/30 px-2 py-0.5 rounded">
                  Non-Mutating
                </span>
              </div>

              <form onSubmit={handleRunSimulation} className="space-y-4">
                {/* Finding Quick Selector */}
                <div>
                  <label htmlFor="finding-select" className="block text-xs font-medium text-slate-300 mb-1">
                    Select Active Finding (Optional)
                  </label>
                  <select
                    id="finding-select"
                    value={findingId}
                    onChange={(e) => handleSelectFinding(e.target.value)}
                    disabled={findingsLoading}
                    className="w-full rounded-lg border border-slate-700 bg-[#0b121a] px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
                  >
                    <option value="">-- Manual or Select Finding --</option>
                    {findingsList.map((f) => (
                      <option key={f.id} value={f.id}>
                        {f.package_name} ({f.package_version}) &bull; {f.advisory_id} ({f.priority})
                      </option>
                    ))}
                  </select>
                </div>

                {/* Package Name */}
                <div>
                  <label htmlFor="pkg-name" className="block text-xs font-medium text-slate-300 mb-1">
                    Package Name <span className="text-red-400">*</span>
                  </label>
                  <input
                    id="pkg-name"
                    type="text"
                    required
                    placeholder="e.g. express, lodash, urllib3"
                    value={packageName}
                    onChange={(e) => setPackageName(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-[#0b121a] px-3 py-2 text-xs text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none font-mono"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  {/* Current Version */}
                  <div>
                    <label htmlFor="curr-ver" className="block text-xs font-medium text-slate-300 mb-1">
                      Installed Version <span className="text-red-400">*</span>
                    </label>
                    <input
                      id="curr-ver"
                      type="text"
                      required
                      placeholder="e.g. 4.17.1"
                      value={currentVersion}
                      onChange={(e) => setCurrentVersion(e.target.value)}
                      className="w-full rounded-lg border border-slate-700 bg-[#0b121a] px-3 py-2 text-xs text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none font-mono"
                    />
                  </div>

                  {/* Target Version */}
                  <div>
                    <label htmlFor="target-ver" className="block text-xs font-medium text-slate-300 mb-1">
                      Target Version <span className="text-red-400">*</span>
                    </label>
                    <input
                      id="target-ver"
                      type="text"
                      required
                      placeholder="e.g. 4.18.2"
                      value={targetVersion}
                      onChange={(e) => setTargetVersion(e.target.value)}
                      className="w-full rounded-lg border border-slate-700 bg-[#0b121a] px-3 py-2 text-xs text-emerald-300 placeholder-slate-500 focus:border-sky-500 focus:outline-none font-mono font-semibold"
                    />
                  </div>
                </div>

                {/* Ecosystem */}
                <div>
                  <label htmlFor="eco-select" className="block text-xs font-medium text-slate-300 mb-1">
                    Ecosystem
                  </label>
                  <select
                    id="eco-select"
                    value={ecosystem}
                    onChange={(e) => setEcosystem(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-[#0b121a] px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
                  >
                    <option value="npm">npm (Node.js)</option>
                    <option value="PyPI">PyPI (Python)</option>
                    <option value="Cargo">Cargo (Rust)</option>
                    <option value="Go">Go Modules</option>
                  </select>
                </div>

                {simError && (
                  <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300 flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
                    <span>{simError}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={isSimulating}
                  className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-2.5 text-xs font-semibold text-white hover:bg-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-500/50 disabled:opacity-50 transition-colors shadow-lg shadow-sky-950/50"
                >
                  {isSimulating ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      <span>Computing Graph Overlay Delta...</span>
                    </>
                  ) : (
                    <>
                      <FlaskConical className="h-4 w-4" />
                      <span>Simulate Fix Delta (AC-1)</span>
                    </>
                  )}
                </button>
              </form>
            </div>

            {/* Recent Project Simulations Card */}
            <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5 text-slate-400" />
                  Recent Project Runs ({history.length})
                </h3>
                <button
                  type="button"
                  onClick={() => activeProject && void loadHistory(activeProject.id)}
                  disabled={historyLoading}
                  className="text-slate-400 hover:text-white transition-colors"
                  title="Refresh simulation history"
                >
                  <RefreshCw className={`h-3 w-3 ${historyLoading ? 'animate-spin' : ''}`} />
                </button>
              </div>

              {history.length === 0 ? (
                <p className="text-xs text-slate-500 py-3 text-center">No recent simulations recorded.</p>
              ) : (
                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                  {history.map((item) => (
                    <button
                      type="button"
                      key={item.id}
                      onClick={() => setSimulation(item)}
                      className={`w-full text-left rounded-lg border p-2.5 text-xs transition-colors ${
                        simulation?.id === item.id
                          ? 'border-sky-500/40 bg-sky-950/20'
                          : 'border-slate-800/80 bg-[#0b121a] hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-semibold text-white">{item.package_name}</span>
                        <span className="text-[10px] text-emerald-400 font-medium">
                          -{item.total_findings_cleared} vuln
                        </span>
                      </div>
                      <div className="mt-1 flex items-center gap-1 text-[11px] text-slate-400 font-mono">
                        <span>v{item.current_version}</span>
                        <span>&rarr;</span>
                        <span className="text-emerald-300">v{item.target_version}</span>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Right Column: Simulation Results Screen */}
          <div className="space-y-6 lg:col-span-2">
            {!simulation ? (
              <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-12 text-center text-slate-400 space-y-4">
                <FlaskConical className="mx-auto h-12 w-12 text-sky-400/60" />
                <div className="max-w-md mx-auto space-y-1.5">
                  <h3 className="text-base font-bold text-white">No Simulation Executed</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Select a finding or specify a package version to simulate upgrading on an ephemeral FalkorDB graph overlay.
                  </p>
                </div>
                <div className="pt-2">
                  <button
                    type="button"
                    onClick={() => {
                      if (findingsList.length > 0) {
                        handleSelectFinding(findingsList[0].id)
                      }
                    }}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition-colors"
                  >
                    <span>Load First Available Finding</span>
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-6">
                {/* Simulation Header Banner */}
                <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-lg font-bold font-mono text-white">
                          {simulation.package_name}
                        </span>
                        <span className="text-xs text-slate-400 font-mono">
                          v{simulation.current_version} &rarr; <strong className="text-emerald-400">v{simulation.target_version}</strong>
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1">
                        Snapshot Baseline: <span className="font-mono text-slate-300">{simulation.baseline_id}</span> &bull; {simulation.ecosystem}
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      {/* AC-2: Explicit Method Label */}
                      <span className="rounded bg-sky-500/15 border border-sky-500/30 px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider text-sky-300 flex items-center gap-1.5">
                        <FlaskConical className="h-3.5 w-3.5 text-sky-400" />
                        Method: {simulation.method === 'simulated_from_metadata' ? 'Simulated from Metadata' : 'Verified in Sandbox'}
                      </span>

                      {/* AC-3: Non-Mutation Guarantee */}
                      <span className="rounded bg-emerald-500/15 border border-emerald-500/30 px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider text-emerald-300 flex items-center gap-1.5">
                        <Check className="h-3.5 w-3.5 text-emerald-400" />
                        Real Graph Untouched (AC-3)
                      </span>
                    </div>
                  </div>

                  {/* Method Description Callout (AC-2) */}
                  <div className="rounded-lg border border-slate-800/80 bg-[#0b121a] p-3 text-xs text-slate-300 flex items-start gap-2.5">
                    <Info className="h-4 w-4 text-sky-400 mt-0.5 shrink-0" />
                    <div>
                      <strong className="text-slate-200">Simulation Methodology: </strong>
                      <span className="text-slate-400">{simulation.method_description}</span>
                    </div>
                  </div>
                </div>

                {/* AC-1: Delta Breakdown Cards (Cleared, Unchanged, Newly Introduced) */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* Cleared Findings */}
                  <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/15 p-4 space-y-1.5 shadow-lg">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                        <ShieldCheck className="h-4 w-4" />
                        Cleared Findings
                      </span>
                      <span className="text-2xl font-extrabold text-emerald-300">
                        {simulation.total_findings_cleared}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-300">
                      Vulnerabilities expected to be resolved by version {simulation.target_version}.
                    </p>
                  </div>

                  {/* Unchanged Findings */}
                  <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-4 space-y-1.5 shadow-lg">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                        <Layers className="h-4 w-4 text-slate-400" />
                        Unchanged Findings
                      </span>
                      <span className="text-2xl font-extrabold text-slate-200">
                        {simulation.total_findings_unchanged}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400">
                      Residual findings or unaffected packages in active services.
                    </p>
                  </div>

                  {/* Newly Introduced Findings */}
                  <div className={`rounded-xl border p-4 space-y-1.5 shadow-lg ${
                    simulation.total_findings_introduced > 0
                      ? 'border-amber-500/40 bg-amber-950/15'
                      : 'border-slate-800 bg-[#0f1822]'
                  }`}>
                    <div className="flex items-center justify-between">
                      <span className={`text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 ${
                        simulation.total_findings_introduced > 0 ? 'text-amber-400' : 'text-slate-400'
                      }`}>
                        <ShieldAlert className="h-4 w-4" />
                        Introduced Delta
                      </span>
                      <span className={`text-2xl font-extrabold ${
                        simulation.total_findings_introduced > 0 ? 'text-amber-300' : 'text-slate-400'
                      }`}>
                        {simulation.total_findings_introduced}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400">
                      New vulnerabilities reported against version {simulation.target_version}.
                    </p>
                  </div>
                </div>

                {/* Graph Exposure & Reachability Metrics */}
                <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-4">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Network className="h-4 w-4 text-sky-400" />
                    Dependency Path Reachability &amp; Blast Radius
                  </h3>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                    <div className="rounded-lg border border-slate-800/80 bg-[#0b121a] p-3 space-y-1">
                      <span className="text-slate-400 block text-[11px]">Dependency Depth</span>
                      <span className="font-mono font-bold text-white text-sm">
                        {simulation.path_depth ?? 'Direct'} {simulation.is_transitive ? '(Transitive)' : '(Direct)'}
                      </span>
                    </div>

                    <div className="rounded-lg border border-slate-800/80 bg-[#0b121a] p-3 space-y-1">
                      <span className="text-slate-400 block text-[11px]">Paths Severed</span>
                      <span className="font-mono font-bold text-emerald-400 text-sm">
                        {simulation.paths_severed_count}
                      </span>
                    </div>

                    <div className="rounded-lg border border-slate-800/80 bg-[#0b121a] p-3 space-y-1">
                      <span className="text-slate-400 block text-[11px]">Paths Remaining</span>
                      <span className="font-mono font-bold text-slate-300 text-sm">
                        {simulation.paths_remaining_count}
                      </span>
                    </div>

                    <div className="rounded-lg border border-slate-800/80 bg-[#0b121a] p-3 space-y-1">
                      <span className="text-slate-400 block text-[11px]">Breaking Risk</span>
                      <span className={`font-mono font-bold uppercase text-sm ${
                        simulation.breaking_change_risk === 'high'
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}>
                        {simulation.breaking_change_risk}
                      </span>
                    </div>
                  </div>

                  {simulation.dependent_services.length > 0 && (
                    <div className="pt-2 text-xs">
                      <span className="text-slate-400">Dependent Services Reachable: </span>
                      <span className="text-slate-200 font-medium">
                        {simulation.dependent_services.join(', ')}
                      </span>
                    </div>
                  )}
                </div>

                {/* Cleared Findings Delta List (AC-1) */}
                <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <ShieldCheck className="h-4 w-4 text-emerald-400" />
                      Findings Cleared Delta ({simulation.cleared_findings.length})
                    </h3>
                  </div>

                  {simulation.cleared_findings.length === 0 ? (
                    <p className="text-xs text-slate-400 italic">No project findings cleared by this version.</p>
                  ) : (
                    <div className="space-y-3">
                      {simulation.cleared_findings.map((item) => (
                        <div
                          key={item.finding_id}
                          className="rounded-lg border border-emerald-500/30 bg-emerald-950/10 p-3.5 space-y-2 text-xs"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-white font-mono">{item.advisory_id}</span>
                              <span className="rounded bg-emerald-500/20 border border-emerald-500/40 px-2 py-0.5 text-[10px] font-bold uppercase text-emerald-300">
                                Expected Resolved
                              </span>
                            </div>
                            <span className="text-slate-400 text-[11px]">Severity: <strong className="text-amber-300">{item.severity}</strong></span>
                          </div>

                          <p className="text-slate-300 text-xs leading-relaxed">
                            {item.explanation}
                          </p>

                          {item.source_url && (
                            <div className="pt-1">
                              <a
                                href={item.source_url}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-1 text-[11px] text-sky-400 hover:underline"
                              >
                                <span>Advisory Reference</span>
                                <ExternalLink className="h-3 w-3" />
                              </a>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Verification Checklist (AC-2 Transparent Boundary) */}
                <div className="rounded-xl border border-slate-800 bg-[#0f1822] p-5 shadow-xl space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-sky-400" />
                      Verification Checklist &amp; Evaluation Boundaries (AC-2)
                    </h3>
                  </div>

                  <div className="space-y-2.5">
                    {simulation.checks_performed.map((chk, idx) => {
                      const isPassed = chk.status === 'passed'
                      const isNotEval = chk.status === 'not_evaluated'

                      return (
                        <div
                          key={idx}
                          className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded-lg border border-slate-800/80 bg-[#0b121a] p-3 text-xs"
                        >
                          <div className="space-y-0.5">
                            <span className="font-semibold text-slate-200">{chk.name}</span>
                            <p className="text-[11px] text-slate-400">{chk.description}</p>
                          </div>

                          <div className="shrink-0 self-start sm:self-auto">
                            {isPassed && (
                              <span className="rounded bg-emerald-500/15 border border-emerald-500/30 px-2 py-0.5 text-[10px] font-bold uppercase text-emerald-300">
                                Passed
                              </span>
                            )}
                            {isNotEval && (
                              <span className="rounded bg-slate-700/40 border border-slate-600 px-2 py-0.5 text-[10px] font-bold uppercase text-slate-400">
                                Not Evaluated
                              </span>
                            )}
                            {!isPassed && !isNotEval && (
                              <span className="rounded bg-amber-500/15 border border-amber-500/30 px-2 py-0.5 text-[10px] font-bold uppercase text-amber-300">
                                {chk.status}
                              </span>
                            )}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>

                {/* Compatibility Caveats & Breaking Risk */}
                {simulation.compatibility_caveats.length > 0 && (
                  <div className="rounded-xl border border-amber-500/30 bg-amber-950/10 p-5 shadow-xl space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-amber-400 flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4" />
                      Compatibility Caveats &amp; Warnings
                    </h3>
                    <ul className="space-y-1.5 text-xs text-slate-300">
                      {simulation.compatibility_caveats.map((c, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="mt-1 h-1.5 w-1.5 rounded-full bg-amber-400 shrink-0" />
                          <span className="leading-relaxed">{c}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Mandatory Safety Disclaimer */}
                <div className="rounded-lg border border-slate-800 bg-[#080d12] p-4 text-xs text-slate-400 flex items-start gap-3">
                  <Info className="h-4 w-4 text-sky-400 mt-0.5 shrink-0" />
                  <div className="space-y-1">
                    <span className="font-semibold text-slate-300">Mandatory Safety Notice:</span>
                    <p className="text-[11px] leading-relaxed text-slate-400">
                      {simulation.safety_disclaimer}
                    </p>
                  </div>
                </div>

                {/* Action Bar */}
                <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => {
                      setSimulation(null)
                    }}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition-colors"
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                    <span>Reset Simulation</span>
                  </button>

                  <Link
                    to={`/github-issues?finding=${encodeURIComponent(findingId || simulation.cleared_findings[0]?.finding_id || '')}&target=${encodeURIComponent(simulation.target_version)}&simId=${encodeURIComponent(simulation.id)}`}
                    className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 transition-colors shadow-lg shadow-emerald-950/50"
                  >
                    <GitPullRequest className="h-4 w-4" />
                    <span>Proceed to Fix Issue Approval</span>
                  </Link>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
